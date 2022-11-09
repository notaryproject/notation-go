package registry

import (
	"context"

	"github.com/notaryproject/notation-go"
	"github.com/opencontainers/go-digest"
)

// SignatureRepository provides a storage for signatures
type SignatureRepository interface {
	// ListSignatureManifests returns all signature manifests given the manifest digest
	ListSignatureManifests(ctx context.Context, manifestDigest digest.Digest) ([]SignatureManifest, error)

	// GetBlob downloads the content of the specified digest's Blob
	GetBlob(ctx context.Context, digest digest.Digest) ([]byte, error)

	// PutSignatureManifest creates and uploads an signature artifact linking the manifest and the signature
	PutSignatureManifest(ctx context.Context, signature []byte, signatureMediaType string, manifest notation.Descriptor, annotations map[string]string) (notation.Descriptor, SignatureManifest, error)
}

// Repository provides functions for verification and signing workflows
type Repository interface {
	SignatureRepository

	// Resolve resolves a reference(tag or digest) to a manifest descriptor
	Resolve(ctx context.Context, reference string) (notation.Descriptor, error)
}
