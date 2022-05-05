package notation

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/notaryproject/notation-go/crypto/timestamp"
	"github.com/notaryproject/notation-go/spec/v1/signature"
)

// SignOptions contains parameters for Signer.Sign.
type SignOptions struct {
	// Expiry identifies the expiration time of the resulted signature.
	Expiry time.Time

	// TSA is the TimeStamp Authority to timestamp the resulted signature if present.
	TSA timestamp.Timestamper

	// TSAVerifyOptions is the verify option to verify the fetched timestamp signature.
	// The `Intermediates` in the verify options will be ignored and re-contrusted using
	// the certificates in the fetched timestamp signature.
	// An empty list of `KeyUsages` in the verify options implies ExtKeyUsageTimeStamping.
	TSAVerifyOptions x509.VerifyOptions
}

// Signer is a generic interface for signing an artifact.
// The interface allows signing with local or remote keys,
// and packing in various signature formats.
type Signer interface {
	// Sign signs the artifact described by its descriptor,
	// and returns the signature.
	Sign(ctx context.Context, desc signature.Descriptor, opts SignOptions) ([]byte, error)
}

// VerifyOptions contains parameters for Verifier.Verify.
type VerifyOptions struct{}

// Validate does basic validation on VerifyOptions.
func (opts VerifyOptions) Validate() error {
	return nil
}

// Verifier is a generic interface for verifying an artifact.
type Verifier interface {
	// Verify verifies the signature and returns the verified descriptor and
	// metadata of the signed artifact.
	Verify(ctx context.Context, signature []byte, opts VerifyOptions) (signature.Descriptor, error)
}

// Service combines the signing and verification services.
type Service interface {
	Signer
	Verifier
}
