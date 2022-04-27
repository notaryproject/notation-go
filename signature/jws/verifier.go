package jws

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/crypto/jwsutil"
	"github.com/notaryproject/notation-go/crypto/timestamp"
)

// maxTimestampAccuracy specifies the max acceptable accuracy for timestamp.
const maxTimestampAccuracy = time.Minute

// Verifier verifies artifacts against JWS signatures.
type Verifier struct {
	// ValidMethods contains a list of acceptable signing methods.
	// Only signing methods in this list are considerred valid if populated.
	ValidMethods []string

	// ResolveSigningMethod resolves the signing method used to verify the certificate in the
	// certificate chain.
	// If not present, `SigningMethodFromKey` will be used to pick up a recommended method.
	ResolveSigningMethod func(interface{}) (jwt.SigningMethod, error)

	// EnforceExpiryValidation enforces the verifier to verify the timestamp signature even if
	// the certificate is valid.
	// Reference: https://github.com/notaryproject/notaryproject/discussions/98
	EnforceExpiryValidation bool

	// VerifyOptions is the verify option to verify the certificate of the incoming signature.
	// The `Intermediates` in the verify options will be ignored and re-contrusted using
	// the certificates in the incoming signature.
	// An empty list of `KeyUsages` in the verify options implies `ExtKeyUsageCodeSigning`.
	VerifyOptions x509.VerifyOptions

	// TSARoots is the set of trusted root certificates for verifying the fetched timestamp
	// signature. If nil, the system roots or the platform verifier are used.
	TSARoots *x509.CertPool
}

// NewVerifier creates a verifier with a set of trusted verification keys.
// Callers may be interested in options in the public field of the Verifier, especially
// VerifyOptions for setting up trusted certificates.
func NewVerifier() *Verifier {
	return &Verifier{}
}

// AddCertPEM decodes data as a PEM certificate
// and adds it to v.VerifyOptions.Roots.
func (v *Verifier) AddCertPEM(data []byte) error {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		certs = append(certs, cert)
	}
	if v.VerifyOptions.Roots == nil {
		v.VerifyOptions.Roots = x509.NewCertPool()
	}
	for _, cert := range certs {
		v.VerifyOptions.Roots.AddCert(cert)
	}
	return nil
}

// Verify verifies the signature and returns the verified descriptor and
// metadata of the signed artifact.
func (v *Verifier) Verify(ctx context.Context, signature []byte, opts notation.VerifyOptions) (notation.Descriptor, error) {
	// unpack envelope
	sig, err := openEnvelope(signature)
	if err != nil {
		return notation.Descriptor{}, err
	}

	// verify signing identity
	method, key, err := v.verifySigner(&sig.Signature)
	if err != nil {
		return notation.Descriptor{}, err
	}

	// verify JWT
	claim, err := v.verifyJWT(method, key, sig.SerializeCompact())
	if err != nil {
		return notation.Descriptor{}, err
	}

	return claim.Subject, nil
}

// verifySigner verifies the signing identity and returns the verification key.
func (v *Verifier) verifySigner(sig *jwsutil.Signature) (jwt.SigningMethod, crypto.PublicKey, error) {
	var header unprotectedHeader
	if err := json.Unmarshal(sig.Unprotected, &header); err != nil {
		return nil, nil, err
	}

	if len(header.CertChain) == 0 {
		return nil, nil, errors.New("signer certificates not found")
	}
	return v.verifySignerFromCertChain(header.CertChain, header.TimeStampToken, sig.Signature)
}

// verifySignerFromCertChain verifies the signing identity from the provided certificate
// chain and returns the verification key. The first certificate of the certificate chain
// contains the key, which used to sign the artifact.
// Reference: RFC 7515 4.1.6 "x5c" (X.509 Certificate Chain) Header Parameter.
func (v *Verifier) verifySignerFromCertChain(certChain [][]byte, timeStampToken []byte, encodedSig string) (jwt.SigningMethod, crypto.PublicKey, error) {
	// prepare for certificate verification
	certs := make([]*x509.Certificate, 0, len(certChain))
	for _, certBytes := range certChain {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, nil, err
		}
		certs = append(certs, cert)
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	verifyOpts := v.VerifyOptions
	verifyOpts.Intermediates = intermediates
	if len(verifyOpts.KeyUsages) == 0 {
		verifyOpts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	}

	// verify the signing certificate
	checkTimestamp := v.EnforceExpiryValidation
	cert := certs[0]
	if _, err := cert.Verify(verifyOpts); err != nil {
		if certErr, ok := err.(x509.CertificateInvalidError); !ok || certErr.Reason != x509.Expired {
			return nil, nil, err
		}

		// verification failed due to expired certificate
		checkTimestamp = true
	}
	if checkTimestamp {
		stampedTime, err := v.verifyTimestamp(timeStampToken, encodedSig)
		if err != nil {
			return nil, nil, err
		}
		verifyOpts.CurrentTime = stampedTime
		if _, err := cert.Verify(verifyOpts); err != nil {
			return nil, nil, err
		}
	}

	// resolve signing method
	resolveMethod := v.ResolveSigningMethod
	if resolveMethod == nil {
		resolveMethod = SigningMethodFromKey
	}
	method, err := resolveMethod(cert.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	return method, cert.PublicKey, nil
}

// verifyTimestamp verifies the timestamp token and returns stamped time.
func (v *Verifier) verifyTimestamp(tokenBytes []byte, encodedSig string) (time.Time, error) {
	sig, err := base64.RawURLEncoding.DecodeString(encodedSig)
	if err != nil {
		return time.Time{}, err
	}
	return verifyTimestamp(sig, tokenBytes, v.TSARoots)
}

// verifyJWT verifies the JWT token against the specified verification key, and
// returns notation claim.
func (v *Verifier) verifyJWT(method jwt.SigningMethod, key crypto.PublicKey, tokenString string) (*notationClaim, error) {
	// parse and verify token
	parser := &jwt.Parser{
		ValidMethods: v.ValidMethods,
	}
	var claims payload
	if _, err := parser.ParseWithClaims(tokenString, &claims, func(t *jwt.Token) (interface{}, error) {
		alg := t.Method.Alg()
		if expectedAlg := method.Alg(); alg != expectedAlg {
			return nil, fmt.Errorf("unexpected signing method: %v: require %v", alg, expectedAlg)
		}

		// override default signing method with key-specific method
		t.Method = method
		return key, nil
	}); err != nil {
		return nil, err
	}

	// ensure required claims exist.
	// Note: the registered claims are already verified by parser.ParseWithClaims().
	if claims.IssuedAt == nil {
		return nil, errors.New("missing iat")
	}
	return &claims.Notation, nil
}

// openEnvelope opens the signature envelope and get the embedded signature.
func openEnvelope(signature []byte) (*jwsutil.CompleteSignature, error) {
	var envelope jwsutil.Envelope
	if err := json.Unmarshal(signature, &envelope); err != nil {
		return nil, err
	}
	if len(envelope.Signatures) != 1 {
		return nil, errors.New("single signature envelope expected")
	}
	sig := envelope.Open()
	return &sig, nil
}

// verifyTimestamp verifies the timestamp token and returns stamped time.
func verifyTimestamp(contentBytes, tokenBytes []byte, roots *x509.CertPool) (time.Time, error) {
	token, err := timestamp.ParseSignedToken(tokenBytes)
	if err != nil {
		return time.Time{}, err
	}
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	if _, err := token.Verify(opts); err != nil {
		return time.Time{}, err
	}
	info, err := token.Info()
	if err != nil {
		return time.Time{}, err
	}
	if err := info.Verify(contentBytes); err != nil {
		return time.Time{}, err
	}
	stampedTime, accuracy := info.Timestamp()
	if accuracy > maxTimestampAccuracy {
		return time.Time{}, fmt.Errorf("max timestamp accuracy exceeded: %v", accuracy)
	}
	return stampedTime, nil
}
