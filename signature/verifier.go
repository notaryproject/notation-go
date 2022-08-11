package signature

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/notaryproject/notation-core-go/signature"
	x509n "github.com/notaryproject/notation-core-go/x509"
	"github.com/notaryproject/notation-go"
)

// // maxTimestampAccuracy specifies the max acceptable accuracy for timestamp.
// const maxTimestampAccuracy = time.Minute

// Verifier verifies artifacts against JWS signatures.
type Verifier struct {
	TrustedCerts []*x509.Certificate
}

// NewVerifier creates a verifier with a set of trusted verification keys.
// Callers may be interested in options in the public field of the Verifier, especially
// VerifyOptions for setting up trusted certificates.
func NewVerifier() *Verifier {
	return &Verifier{}
}

// NewVerifierFromFiles creates a verifier from certificate files
func NewVerifierFromFiles(certPaths []string) (*Verifier, error) {
	certs := make([]*x509.Certificate, len(certPaths))
	for _, path := range certPaths {
		cs, err := x509n.ReadCertificateFile(path)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cs...)
	}
	return &Verifier{TrustedCerts: certs}, nil
}

// Verify verifies the signature and returns the verified descriptor and
// metadata of the signed artifact.
func (v *Verifier) Verify(_ context.Context, sig []byte, opts notation.VerifyOptions) (notation.Descriptor, error) {
	sigEnv, err := signature.ParseEnvelope(opts.SignatureMediaType, sig)
	if err != nil {
		return notation.Descriptor{}, err
	}

	sigPayload, signerInfo, err := sigEnv.Verify()
	if err != nil {
		return notation.Descriptor{}, err
	}

	_, authErr := signature.VerifyAuthenticity(signerInfo, v.TrustedCerts)
	if authErr != nil {
		return notation.Descriptor{}, authErr
	}

	// TODO: validate expiry and timestamp https://github.com/notaryproject/notation-go/issues/78
	var payload notation.Payload
	if err = json.Unmarshal(sigPayload.Content, &payload); err != nil {
		return notation.Descriptor{}, fmt.Errorf("envelope payload can't be decoded: %w", err)
	}

	return payload.TargetArtifact, nil
}
