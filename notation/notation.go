package notation

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/timestamp"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry"
)

// Descriptor describes the artifact that needs to be signed.
type Descriptor struct {
	// The media type of the targeted content.
	MediaType string `json:"mediaType"`

	// The digest of the targeted content.
	Digest digest.Digest `json:"digest"`

	// Specifies the size in bytes of the blob.
	Size int64 `json:"size"`

	// Contains optional user defined attributes.
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Equal reports whether d and t points to the same content.
func (d Descriptor) Equal(t Descriptor) bool {
	return d.MediaType == t.MediaType && d.Digest == t.Digest && d.Size == t.Size
}

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

	// Sets or overrides the plugin configuration.
	PluginConfig map[string]string
}

// Signer is a generic interface for signing an artifact.
// The interface allows signing with local or remote keys,
// and packing in various signature formats.
type Signer interface {
	// Sign signs the artifact described by its descriptor,
	// and returns the signature and SignerInfo.
	Sign(ctx context.Context, desc Descriptor, opts SignOptions) ([]byte, *signature.SignerInfo, error)
}

// Sign signs the artifact in the remote registry and push the signature to the remote.
// The descriptor of the sign content is returned upon sucessful signing.
func Sign(ctx context.Context, signer Signer, repo registry.Repository, reference string, opts SignOptions) (Descriptor, error) {
	ref, err := registry.ParseReference(reference)
	if err != nil {
		return Descriptor{}, err
	}
	desc, err := repo.Resolve(ctx, ref.ReferenceOrDefault())
	if err != nil {
		return Descriptor{}, err
	}
	artifactManifestDesc := notationDescriptorFromOCI(desc)
	sig, signerInfo, err := signer.Sign(ctx, artifactManifestDesc, opts)

	return artifactManifestDesc, nil
}

// VerifyOptions contains parameters for Verifier.Verify.
type VerifyOptions struct {
	ArtifactReference string
	// SignatureMediaType is the envelope type of the signature.
	// Currently both `application/jose+json` and `application/cose` are supported.
	SignatureMediaType string
	PluginConfig       map[string]string
	// VerificationDetails any // Export verification details
}

// Verifier is a generic interface for verifying an artifact.
type Verifier interface {
	// Verify verifies the signature and returns the verified descriptor upon
	// successful verification.
	Verify(ctx context.Context, signature []byte, opts VerifyOptions) (Descriptor, error)
}

func notationDescriptorFromOCI(desc ocispec.Descriptor) Descriptor {
	return Descriptor{
		MediaType: desc.MediaType,
		Digest:    desc.Digest,
		Size:      desc.Size,
	}
}
