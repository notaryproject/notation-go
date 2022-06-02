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
func NewSigner(key crypto.PrivateKey, certChain []*x509.Certificate) (notation.Signer, error) {
	if key == nil {
		return nil, errors.New("nil signing key")
	}
	if len(certChain) == 0 {
		return nil, errors.New("missing signer certificate chain")
	}
	keySpec, err := keySpecFromKey(key)
	if err != nil {
		return nil, err
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

	rawCerts := make([][]byte, len(certChain))
	for i, cert := range certChain {
		rawCerts[i] = cert.Raw
	}
	return &pluginSigner{
		runner: &builtinPlugin{
			keySpec:   keySpec,
			key:       key,
			certChain: rawCerts,
		},
	}, nil
}

// builtinPlugin is a plugin.Runner implementation which
// signs supports the generate-signature workflow using
// the provided key and certificates.
type builtinPlugin struct {
	keySpec notation.KeySpec

	// key is the signing key used to sign artifacts.
	key crypto.PrivateKey

	// certChain contains the X.509 public key certificate or certificate chain corresponding
	// to the key used to generate the signature.
	certChain [][]byte
}

func (builtinPlugin) metadata() *plugin.Metadata {
	// The only properties that are really relevant
	// are the supported contract version and the capabilities.
	// All other are just filled with meaningful data.
	return &plugin.Metadata{
		SupportedContractVersions: []string{plugin.ContractVersion},
		Capabilities:              []plugin.Capability{plugin.CapabilitySignatureGenerator},
		Name:                      "built-in",
		Description:               "Notation built-in signer",
		Version:                   plugin.ContractVersion,
		URL:                       "https://github.com/notaryproject/notation-go",
	}
}

// Run implement the generate-signature workflow.
func (r *builtinPlugin) Run(ctx context.Context, req plugin.Request) (interface{}, error) {
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
		// TODO: the builtinPlugin should be JWS-agnostic.
		// Stop using a jwt.MethodSigner and use instead
		// the hash provided in req1.Hash and a Sign method
		// which does not hash data itself.
		sigAlg := r.keySpec.SignatureAlgorithm()
		method := jwt.GetSigningMethod(sigAlg.JWS())
		signed, err := method.Sign(string(req1.Payload), r.key)
		if err != nil {
			return nil, plugin.RequestError{
				Code: plugin.ErrorCodeGeneric,
				Err:  err,
			}
		}
		// jwt.Sign returns a base64url-encoded encoded signature,
		// but GenerateSignatureResponse.Signature expects it to be decoded.
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
			SigningAlgorithm: sigAlg,
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
			"cty": notation.MediaTypePayload,
		},
		Claims: claims,
	}
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
