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
	"github.com/notaryproject/notation-go/spec/v1/signature"
)

// Signer signs artifacts and generates JWS signatures.
type Signer struct {
	// method is the method to sign artifacts.
	method jwt.SigningMethod

	// key is the signing key used to sign artifacts.
	// The signing key can be either remote or local.
	key crypto.PrivateKey

	// certChain contains the X.509 public key certificate or certificate chain corresponding
	// to the key used to generate the signature.
	certChain []string
}

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

	rawCerts := make([]string, len(certChain))
	for i, cert := range certChain {
		rawCerts[i] = base64.RawStdEncoding.EncodeToString(cert.Raw)
	}
	return &Signer{
		method:    method,
		key:       key,
		certChain: rawCerts,
	}, nil
}

// Sign signs the artifact described by its descriptor, and returns the signature.
func (s *Signer) Sign(ctx context.Context, desc signature.Descriptor, opts notation.SignOptions) ([]byte, error) {
	// generate JWT
	payload := packPayload(desc, opts)
	if err := payload.Valid(); err != nil {
		return nil, err
	}
	token := jwtToken(s.method.Alg(), payload)
	token.Method = s.method
	compact, err := token.SignedString(s.key)
	if err != nil {
		return nil, err
	}
	return jwtEnvelop(ctx, opts, compact, s.certChain)
}

func jwtToken(alg string, claims jwt.Claims) *jwt.Token {
	return &jwt.Token{
		Header: map[string]interface{}{
			"alg": alg,
			"cty": signature.MediaTypeJWSEnvelope,
		},
		Claims: claims,
	}
}

func jwtEnvelop(ctx context.Context, opts notation.SignOptions, compact string, certChain []string) ([]byte, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid compact serialization")
	}
	envelope := signature.JWSEnvelope{
		Protected: parts[0],
		Payload:   parts[1],
		Signature: parts[2],
		Header: signature.JWSUnprotectedHeader{
			CertChain: certChain,
		},
	}

	// timestamp JWT
	if opts.TSA != nil {
		token, err := timestampSignature(ctx, envelope.Signature, opts.TSA, opts.TSAVerifyOptions)
		if err != nil {
			return nil, fmt.Errorf("timestamp failed: %w", err)
		}
		envelope.Header.TimeStampToken = base64.RawStdEncoding.EncodeToString(token)
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
