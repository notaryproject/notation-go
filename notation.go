package notation

import (
	"context"
	"time"

	"github.com/opencontainers/go-digest"
)

// Descriptor describes the content signed or to be signed.
type Descriptor struct {
	// MediaType is the media type of the targeted content.
	MediaType string `json:"mediaType"`

	// Digest is the digest of the targeted content.
	Digest digest.Digest `json:"digest"`

	// Size specifies the size in bytes of the blob.
	Size int64 `json:"size"`
}

// Metadata contains informational metadata about the signed artifact.
type Metadata struct {
	// Identity describes the artifact identity.
	Identity string

	// Attributes contains user defined attributes.
	Attributes map[string]interface{}
}

// SignOptions contains parameters for Signer.Sign.
type SignOptions struct {
	// Expiry identifies the expiration time of the resulted signature.
	// This parameter is REQUIRED.
	Expiry time.Time

	// Metadata is optional for the artifact to be signed.
	Metadata Metadata
}

// Validate does basic validation on SignOptions.
func (opts SignOptions) Validate() error {
	if opts.Expiry.IsZero() {
		return ErrExpiryNotSpecified
	}
	return nil
}

// Signer is an generic interface for signing an artifact.
// The interface allows signing with local or remote keys,
// and packing in various signature formats.
type Signer interface {
	// Sign signs the artifact described by its descriptor,
	// and returns the signature.
	Sign(ctx context.Context, desc Descriptor, opts SignOptions) ([]byte, error)
}

// VerifyOptions contains parameters for Verifier.Verify.
type VerifyOptions struct{}

// Validate does basic validation on VerifyOptions.
func (opts VerifyOptions) Validate() error {
	return nil
}

// Verifier is an generic interface for verifying an artifact.
type Verifier interface {
	// Verify verifies the artifact described by its descriptor against the signature.
	Verify(ctx context.Context, desc Descriptor, signature []byte, opts VerifyOptions) (Metadata, error)
}

// Service combines the signing and verification services.
type Service interface {
	Signer
	Verifier
}
