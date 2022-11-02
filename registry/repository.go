package registry

import (
	"context"

	"github.com/notaryproject/notation-go"
	"oras.land/oras-go/v2/registry/remote"
)

// Repository provides registry functionalities for remote signing and
// verification.
type Repository interface {
	// Resolve resolves a reference(tag or digest) to a manifest descriptor
	Resolve(ctx context.Context, reference string) (notation.Descriptor, error)
	// ListSignatures returns signature manifests filtered by fn given the
	// artifact manifest descriptor
	ListSignatures(ctx context.Context, desc notation.Descriptor, fn func(signatureManifests []notation.Descriptor) error) error
	// FetchSignatureBlob returns signature envelope blob and descriptor given
	// signature manifest descriptor
	FetchSignatureBlob(ctx context.Context, desc notation.Descriptor) ([]byte, notation.Descriptor, error)
	// PushSignature creates and uploads an signature manifest along with its
	// linked signature envelope blob.
	PushSignature(ctx context.Context, blob []byte, mediaType string, subject notation.Descriptor, annotations map[string]string) (blobDesc, manifestDesc notation.Descriptor, err error)
}

// NewRepository returns a new Repository
func NewRepository(repo remote.Repository) Repository {
	return &repositoryClient{
		Repository: repo,
	}
}
