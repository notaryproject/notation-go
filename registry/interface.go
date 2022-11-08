// Package registry provides Repository for remote signing and verification
package registry

import (
	"context"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Repository provides registry functionalities for remote signing and
// verification.
type Repository interface {
	// Resolve resolves a reference(tag or digest) to a manifest descriptor
	Resolve(ctx context.Context, reference string) (ocispec.Descriptor, error)
	// ListSignatures returns signature manifests filtered by fn given the
	// artifact manifest descriptor
	ListSignatures(ctx context.Context, desc ocispec.Descriptor, fn func(signatureManifests []ocispec.Descriptor) error) error
	// FetchSignatureBlob returns signature envelope blob and descriptor given
	// signature manifest descriptor
	FetchSignatureBlob(ctx context.Context, desc ocispec.Descriptor) ([]byte, ocispec.Descriptor, error)
	// PushSignature creates and uploads an signature manifest along with its
	// linked signature envelope blob.
	PushSignature(ctx context.Context, blob []byte, mediaType string, subject ocispec.Descriptor, annotations map[string]string) (blobDesc, manifestDesc ocispec.Descriptor, err error)
}
