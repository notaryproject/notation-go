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
	Lookup(ctx context.Context, manifestDigest digest.Digest) ([]digest.Digest, error)
	Get(ctx context.Context, signatureDigest digest.Digest) ([]byte, error)
	Put(ctx context.Context, signature []byte) (oci.Descriptor, error)
	Link(ctx context.Context, manifest, signature oci.Descriptor) error
}
