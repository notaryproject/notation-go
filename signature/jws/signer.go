package jws

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
	"github.com/notaryproject/notation-go-lib"
	"github.com/notaryproject/notation-go-lib/crypto/jwsutil"
	"github.com/notaryproject/notation-go-lib/crypto/timestamp"
	"github.com/notaryproject/notation-go-lib/internal/crypto/pki"
)

// Signer signs artifacts and generates JWS signatures.
type Signer struct {
	// method is the method to sign artifacts.
	method jwt.SigningMethod

	// key is the signing key used to sign artifacts.
	// The signing key can be either remote or local.
	key crypto.PrivateKey

	// keyID indicates which key is used to generate the signature.
	keyID string

	// certChain contains the X.509 public key certificate or certificate chain corresponding
	// to the key used to generate the signature.
	certChain [][]byte

	// TSA is the TimeStamp Authority to timestamp the resulted signature if present.
	TSA timestamp.Timestamper
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
// a signing key bundled with a certificate chain.
// The relation of the provided siging key and its certificate chain is not verified,
// and should be verified by the caller.
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

	rawCerts := make([][]byte, 0, len(certChain))
	for _, cert := range certChain {
		rawCerts = append(rawCerts, cert.Raw)
	}
	return &Signer{
		method:    method,
		key:       key,
		certChain: rawCerts,
	}, nil
}

// NewSignerWithKeyID creates a signer with the specified signing method and a signing key
// identified by a key ID.
func NewSignerWithKeyID(method jwt.SigningMethod, key crypto.PrivateKey, keyID string) (*Signer, error) {
	if keyID == "" {
		return nil, errors.New("empty signer key ID")
	}

	return &Signer{
		method: method,
		key:    key,
		keyID:  keyID,
	}, nil
}

// Sign signs the artifact described by its descriptor, and returns the signature.
func (s *Signer) Sign(ctx context.Context, desc notation.Descriptor, opts notation.SignOptions) ([]byte, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	// generate JWT
	payload := packPayload(desc, opts)
	if err := payload.Valid(); err != nil {
		return nil, err
	}
	token := &jwt.Token{
		Header: map[string]interface{}{
			"alg": s.method.Alg(),
			"cty": MediaTypeNotationPayload,
			"crit": []string{
				"cty",
			},
		},
		Claims: payload,
		Method: s.method,
	}
	compact, err := token.SignedString(s.key)
	if err != nil {
		return nil, err
	}

	// generate unprotected header
	header := unprotectedHeader{
		KeyID:     s.keyID,
		CertChain: s.certChain,
	}

	// timestamp JWT
	sig, err := jwsutil.ParseCompact(compact)
	if err != nil {
		return nil, err
	}
	if s.TSA != nil {
		decodedSig, err := base64.RawURLEncoding.DecodeString(sig.Signature.Signature)
		if err != nil {
			return nil, err
		}
		req, err := timestamp.NewRequestFromBytes(decodedSig)
		if err != nil {
			return nil, err
		}
		resp, err := s.TSA.Timestamp(ctx, req)
		if err != nil {
			return nil, err
		}
		if status := resp.Status; status.Status != pki.StatusGranted {
			return nil, fmt.Errorf("tsa: %d: %v", status.Status, status.StatusString)
		}
		header.TimeStampToken = resp.TokenBytes()
	}

	// finalize unprotected header
	sig.Unprotected, err = json.Marshal(header)
	if err != nil {
		return nil, err
	}

	// encode in flatten JWS JSON serialization
	return json.Marshal(sig)
}
