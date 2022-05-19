package jws

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/crypto/timestamp"
	"github.com/notaryproject/notation-go/internal/crypto/pki"
	"github.com/notaryproject/notation-go/plugin"
)

// NewSigner creates a signer with the recommended signing method and a signing key bundled
// with a certificate chain.
// The relation of the provided siging key and its certificate chain is not verified,
// and should be verified by the caller.
func NewSigner(key crypto.PrivateKey, certChain []*x509.Certificate) (*Signer, error) {
	method, err := SigningMethodFromKey(key)
	if err != nil {
		return nil, err
	}
	return NewSignerWithCertificateChain(method, key, certChain)
}

// NewSignerWithCertificateChain creates a signer with the specified signing method and
// a signing key bundled with a (partial) certificate chain.
// Since the provided signing key could potentially be a remote key, the relation of the
// siging key and its certificate chain is not verified, and should be verified by the caller.
func NewSignerWithCertificateChain(method jwt.SigningMethod, key crypto.PrivateKey, certChain []*x509.Certificate) (*Signer, error) {
	if method == nil {
		return nil, errors.New("nil signing method")
	}
	if key == nil {
		return nil, errors.New("nil signing key")
	}
	if len(certChain) == 0 {
		return nil, errors.New("missing signer certificate chain")
	}

	// verify the signing certificate
	cert := certChain[0]
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}); err != nil {
		return nil, err
	}

	keySpec, err := keySpecFromJWS(method.Alg())
	if err != nil {
		return nil, err
	}

	rawCerts := make([][]byte, len(certChain))
	for i, cert := range certChain {
		rawCerts[i] = cert.Raw
	}
	return &Signer{
		runner: &inMemoryRunner{
			keySpec:   keySpec,
			method:    method,
			key:       key,
			certChain: rawCerts,
		},
	}, nil
}

type inMemoryRunner struct {
	keySpec notation.KeySpec

	// method is the method to sign artifacts.
	method jwt.SigningMethod

	// key is the signing key used to sign artifacts.
	// The signing key can be either remote or local.
	key crypto.PrivateKey

	// certChain contains the X.509 public key certificate or certificate chain corresponding
	// to the key used to generate the signature.
	certChain [][]byte
}

func (inMemoryRunner) metadata() *plugin.Metadata {
	return &plugin.Metadata{
		Name:                      "builtin-jws",
		Description:               "Build in JWS signer",
		Version:                   plugin.ContractVersion,
		SupportedContractVersions: []string{plugin.ContractVersion},
		URL:                       "https://github.com/notaryproject/notation-go",
		Capabilities:              []plugin.Capability{plugin.CapabilitySignatureGenerator},
	}
}

func (r *inMemoryRunner) Run(ctx context.Context, req plugin.Request) (interface{}, error) {
	switch req.Command() {
	case plugin.CommandGetMetadata:
		return r.metadata(), nil
	case plugin.CommandDescribeKey:
		req1 := req.(*plugin.DescribeKeyRequest)
		return &plugin.DescribeKeyResponse{
			KeyID:   req1.KeyID,
			KeySpec: r.keySpec,
		}, nil
	case plugin.CommandGenerateSignature:
		req1 := req.(*plugin.GenerateSignatureRequest)
		signed, err := r.method.Sign(string(req1.Payload), r.key)
		if err != nil {
			return nil, plugin.RequestError{
				Code: plugin.ErrorCodeGeneric,
				Err:  err,
			}
		}
		signedDecoded, err := base64.RawURLEncoding.DecodeString(signed)
		if err != nil {
			return nil, plugin.RequestError{
				Code: plugin.ErrorCodeGeneric,
				Err:  err,
			}
		}
		return &plugin.GenerateSignatureResponse{
			KeyID:            req1.KeyID,
			Signature:        signedDecoded,
			SigningAlgorithm: req1.KeySpec.SignatureAlgorithm(),
			CertificateChain: r.certChain,
		}, nil
	}
	return nil, plugin.RequestError{
		Code: plugin.ErrorCodeGeneric,
		Err:  fmt.Errorf("command %q is not supported", req.Command()),
	}
}

func jwtToken(alg string, claims jwt.Claims) *jwt.Token {
	return &jwt.Token{
		Header: map[string]interface{}{
			"alg": alg,
			"cty": notation.MediaTypeJWSEnvelope,
		},
		Claims: claims,
	}
}

func keySpecFromJWS(alg string) (notation.KeySpec, error) {
	var keySpec notation.KeySpec
	switch alg {
	case jwt.SigningMethodES256.Name:
		keySpec = notation.EC_256
	case jwt.SigningMethodES384.Name:
		keySpec = notation.EC_384
	case jwt.SigningMethodES512.Name:
		keySpec = notation.EC_512
	case jwt.SigningMethodPS256.Name:
		keySpec = notation.RSA_2048
	case jwt.SigningMethodPS384.Name:
		keySpec = notation.RSA_3072
	case jwt.SigningMethodPS512.Name:
		keySpec = notation.RSA_4096
	default:
		return "", fmt.Errorf("algorithm %q is not supported", alg)
	}
	return keySpec, nil
}

func jwsEnvelope(ctx context.Context, opts notation.SignOptions, compact string, certChain [][]byte) ([]byte, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid compact serialization")
	}
	envelope := notation.JWSEnvelope{
		Protected: parts[0],
		Payload:   parts[1],
		Signature: parts[2],
		Header: notation.JWSUnprotectedHeader{
			CertChain: certChain,
		},
	}

	// timestamp JWT
	if opts.TSA != nil {
		token, err := timestampSignature(ctx, envelope.Signature, opts.TSA, opts.TSAVerifyOptions)
		if err != nil {
			return nil, fmt.Errorf("timestamp failed: %w", err)
		}
		envelope.Header.TimeStampToken = token
	}

	// encode in flatten JWS JSON serialization
	return json.Marshal(envelope)
}

// timestampSignature sends a request to the TSA for timestamping the signature.
func timestampSignature(ctx context.Context, sig string, tsa timestamp.Timestamper, opts x509.VerifyOptions) ([]byte, error) {
	// timestamp the signature
	decodedSig, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return nil, err
	}
	req, err := timestamp.NewRequestFromBytes(decodedSig)
	if err != nil {
		return nil, err
	}
	resp, err := tsa.Timestamp(ctx, req)
	if err != nil {
		return nil, err
	}
	if status := resp.Status; status.Status != pki.StatusGranted {
		return nil, fmt.Errorf("tsa: %d: %v", status.Status, status.StatusString)
	}
	tokenBytes := resp.TokenBytes()

	// verify the timestamp signature
	if _, err := verifyTimestamp(decodedSig, tokenBytes, opts.Roots); err != nil {
		return nil, err
	}

	return tokenBytes, nil
}
