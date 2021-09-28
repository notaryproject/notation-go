package jws

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/notaryproject/notation-go-lib"
	"github.com/notaryproject/notation-go-lib/crypto/jwsutil"
	"github.com/notaryproject/notation-go-lib/crypto/timestamp"
)

// maxTimestampAccuracy specifies the max acceptable accuracy for timestamp.
const maxTimestampAccuracy = time.Minute

// VerificationKey verifies artifacts against JWS signatures.
type VerificationKey struct {
	// id is the key ID.
	id string

	// value is the embedded singing key key.
	value crypto.PublicKey

	// method is the method to verify artifacts.
	method jwt.SigningMethod
}

// NewVerificationKey associate a verification key with the recommended signing method
// and a key ID.
func NewVerificationKey(key crypto.PublicKey, keyID string) (*VerificationKey, error) {
	method, err := SigningMethodFromKey(key)
	if err != nil {
		return nil, err
	}
	return NewVerificationKeyWithKeyID(method, key, keyID)
}

// NewVerificationKeyWithKeyID associate a verification key with the specified signing method
// and a key ID.
func NewVerificationKeyWithKeyID(method jwt.SigningMethod, key crypto.PublicKey, keyID string) (*VerificationKey, error) {
	if key == nil {
		return nil, errors.New("nil signing key")
	}
	if keyID == "" {
		return nil, errors.New("empty signer key ID")
	}

	return &VerificationKey{
		id:     keyID,
		value:  key,
		method: method,
	}, nil
}

// Verifier verifies artifacts against JWS signatures.
type Verifier struct {
	// keys is a set of verification keys indexed by key id.
	keys map[string]*VerificationKey

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

	// TSAVerifyOptions is the verify option to verify the fetched timestamp signature.
	// The `Intermediates` in the verify options will be ignored and re-contrusted using
	// the certificates in the fetched timestamp signature.
	// An empty list of `KeyUsages` in the verify options implies `ExtKeyUsageTimeStamping`.
	TSAVerifyOptions x509.VerifyOptions
}

// NewVerifier creates a verifier with a set of trusted verification keys.
// Callers may be interested in options in the public field of the Verifier, especially
// VerifyOptions for setting up trusted certificates.
func NewVerifier(keys []*VerificationKey) *Verifier {
	indexedKeys := make(map[string]*VerificationKey)
	for _, key := range keys {
		if key.id != "" {
			indexedKeys[key.id] = key
		}
	}
	return &Verifier{
		keys: indexedKeys,
	}
}

// Verify verifies the signature and returns the verified descriptor and
// metadata of the signed artifact.
func (v *Verifier) Verify(ctx context.Context, signature []byte, opts notation.VerifyOptions) (notation.Descriptor, notation.Metadata, error) {
	// unpack envelope
	sig, err := openEnvelope(signature)
	if err != nil {
		return notation.Descriptor{}, notation.Metadata{}, err
	}

	// verify signing identity
	key, err := v.verifySigner(&sig.Signature)
	if err != nil {
		return notation.Descriptor{}, notation.Metadata{}, err
	}

	// verify JWT
	claim, err := v.verifyJWT(sig.SerializeCompact(), key)
	if err != nil {
		return notation.Descriptor{}, notation.Metadata{}, err
	}

	// extract metadata
	var identity string
	if value := claim.SignedAttributes.Reserved["identity"]; value != nil {
		var ok bool
		if identity, ok = value.(string); !ok {
			return notation.Descriptor{}, notation.Metadata{}, errors.New("attribute: invalid identity")
		}
	}

	return claim.SubjectManifest, notation.Metadata{
		Identity:   identity,
		Attributes: claim.SignedAttributes.Custom,
	}, nil
}

// verifySigner verifies the signing identity and returns the verification key.
func (v *Verifier) verifySigner(sig *jwsutil.Signature) (*VerificationKey, error) {
	var header unprotectedHeader
	if err := json.Unmarshal(sig.Unprotected, &header); err != nil {
		return nil, err
	}

	if header.KeyID != "" {
		if len(header.CertChain) != 0 {
			return nil, errors.New("ambiguous signing identities")
		}
		if key, ok := v.keys[header.KeyID]; ok {
			return key, nil
		}
		return nil, fmt.Errorf("unknown key id: %s", header.KeyID)
	} else if len(header.CertChain) != 0 {
		return v.verifySignerFromCertChain(header.CertChain, header.TimeStampToken, sig.Signature)
	}
	return nil, errors.New("signing identity not found")
}

// verifySignerFromCertChain verifies the signing identity from the provided certificate
// chain and returns the verification key. The first certificate of the certificate chain
// contains the key, which used to sign the artifact.
// Reference: RFC 7515 4.1.6 "x5c" (X.509 Certificate Chain) Header Parameter.
func (v *Verifier) verifySignerFromCertChain(certChain [][]byte, timeStampToken []byte, encodedSig string) (*VerificationKey, error) {
	// prepare for certificate verification
	certs := make([]*x509.Certificate, 0, len(certChain))
	for _, certBytes := range certChain {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, err
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
			return nil, err
		}

		// verification failed due to expired certificate
		checkTimestamp = true
	}
	if checkTimestamp {
		stampedTime, err := v.verifyTimestamp(timeStampToken, encodedSig)
		if err != nil {
			return nil, err
		}
		verifyOpts.CurrentTime = stampedTime
		if _, err := cert.Verify(verifyOpts); err != nil {
			return nil, err
		}
	}

	// resolve signing method
	resolveMethod := v.ResolveSigningMethod
	if resolveMethod == nil {
		resolveMethod = SigningMethodFromKey
	}
	method, err := resolveMethod(cert.PublicKey)
	if err != nil {
		return nil, err
	}

	return &VerificationKey{
		value:  cert.PublicKey,
		method: method,
	}, nil
}

// verifyTimestamp verifies the timestamp token and returns stamped time.
func (v *Verifier) verifyTimestamp(tokenBytes []byte, encodedSig string) (time.Time, error) {
	sig, err := base64.RawURLEncoding.DecodeString(encodedSig)
	if err != nil {
		return time.Time{}, err
	}
	return verifyTimestamp(sig, tokenBytes, v.TSAVerifyOptions)
}

// verifyJWT verifies the JWT token against the specified verification key, and
// returns notation claim.
func (v *Verifier) verifyJWT(tokenString string, key *VerificationKey) (*notationClaim, error) {
	// parse and verify token
	parser := &jwt.Parser{
		ValidMethods: v.ValidMethods,
	}
	var claims payload
	if _, err := parser.ParseWithClaims(tokenString, &claims, func(t *jwt.Token) (interface{}, error) {
		alg := t.Method.Alg()
		if expectedAlg := key.method.Alg(); alg != expectedAlg {
			return nil, fmt.Errorf("unexpected signing method: %v: require %v", alg, expectedAlg)
		}

		// override default signing method with key-specific method
		t.Method = key.method
		return key.value, nil
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
func verifyTimestamp(contentBytes, tokenBytes []byte, opts x509.VerifyOptions) (time.Time, error) {
	token, err := timestamp.ParseSignedToken(tokenBytes)
	if err != nil {
		return time.Time{}, err
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
