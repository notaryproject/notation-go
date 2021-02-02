package notary

import (
	"context"

	"github.com/opencontainers/go-digest"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
)

// SignatureRegistry provides signature repositories
type SignatureRegistry interface {
	Repository(ctx context.Context, name string) SignatureRepository
}

// SignatureRepository provides a storage for signatures
type SignatureRepository interface {
	// Lookup finds all signature artifact for the specified manifest
	Lookup(ctx context.Context, manifestDigest digest.Digest) ([]digest.Digest, error)

	// Get downloads the signature by the specified artifact
	Get(ctx context.Context, artifactDigest digest.Digest) ([]byte, digest.Digest, error)

	// Put uploads the signature to the registry
	Put(ctx context.Context, signature []byte) (oci.Descriptor, error)

	// Link creates an signature artifact linking the manifest and the signature
	Link(ctx context.Context, manifest, signature oci.Descriptor) (oci.Descriptor, error)
}
