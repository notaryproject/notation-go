package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	artifactspec "github.com/oras-project/artifacts-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry/remote"
)

const (
	maxBlobSizeLimit     = 32 * 1024 * 1024 // 32 MiB
	maxManifestSizeLimit = 4 * 1024 * 1024  // 4 MiB
)

// repositoryClient implements Repository
type repositoryClient struct {
	remote.Repository
}

// NewRepository returns a new Repository
func NewRepository(repo remote.Repository) Repository {
	return &repositoryClient{
		Repository: repo,
	}
}

// Resolve resolves a reference(tag or digest) to a manifest descriptor
func (c *repositoryClient) Resolve(ctx context.Context, reference string) (ocispec.Descriptor, error) {
	return c.Repository.Resolve(ctx, reference)
}

// ListSignatures returns signature manifests filtered by fn given the
// artifact manifest descriptor
func (c *repositoryClient) ListSignatures(ctx context.Context, desc ocispec.Descriptor, fn func(signatureManifests []ocispec.Descriptor) error) error {
	return c.Repository.Referrers(ctx, ocispec.Descriptor{
		Digest: desc.Digest,
	}, ArtifactTypeNotation, func(referrers []ocispec.Descriptor) error {
		var sigManifestDesc []ocispec.Descriptor
		sigManifestDesc = append(sigManifestDesc, referrers...)
		return fn(sigManifestDesc)
	})
}

// FetchSignatureBlob returns signature envelope blob and descriptor given
// signature manifest descriptor
func (c *repositoryClient) FetchSignatureBlob(ctx context.Context, desc ocispec.Descriptor) ([]byte, ocispec.Descriptor, error) {
	sigManifest, err := c.getSignatureManifest(ctx, desc)
	if err != nil {
		return nil, ocispec.Descriptor{}, err
	}
	if len(sigManifest.Blobs) == 0 {
		return nil, ocispec.Descriptor{}, errors.New("signature manifest missing signature envelope blob")
	}
	sigDesc := ociDescriptorFromArtifact(sigManifest.Blobs[0])
	if sigDesc.Size > maxBlobSizeLimit {
		return nil, ocispec.Descriptor{}, fmt.Errorf("signature blob too large: %d", sigDesc.Size)
	}
	sigBlob, err := content.FetchAll(ctx, c.Repository.Blobs(), sigDesc)
	if err != nil {
		return nil, ocispec.Descriptor{}, err
	}
	return sigBlob, sigDesc, nil
}

// PushSignature creates and uploads an signature manifest along with its
// linked signature envelope blob. Upon successful, PushSignature returns
// signature envelope blob and manifest descriptors.
func (c *repositoryClient) PushSignature(ctx context.Context, blob []byte, mediaType string, subject ocispec.Descriptor, annotations map[string]string) (blobDesc, manifestDesc ocispec.Descriptor, err error) {
	blobDesc, err = c.uploadSignature(ctx, blob, mediaType)
	if err != nil {
		return ocispec.Descriptor{}, ocispec.Descriptor{}, err
	}

	manifestDesc, err = c.uploadSignatureManifest(ctx, subject, blobDesc, annotations)
	if err != nil {
		return ocispec.Descriptor{}, ocispec.Descriptor{}, err
	}

	return blobDesc, manifestDesc, nil
}

// getSignatureManifest returns signature manifest given signature manifest
// descriptor
func (c *repositoryClient) getSignatureManifest(ctx context.Context, sigManifestDesc ocispec.Descriptor) (*artifactspec.Manifest, error) {

	repo := c.Repository
	repo.ManifestMediaTypes = []string{
		artifactspec.MediaTypeArtifactManifest,
	}
	store := repo.Manifests()
	if sigManifestDesc.Size > maxManifestSizeLimit {
		return &artifactspec.Manifest{}, fmt.Errorf("manifest too large: %d", sigManifestDesc.Size)
	}
	manifestJSON, err := content.FetchAll(ctx, store, sigManifestDesc)
	if err != nil {
		return &artifactspec.Manifest{}, err
	}

	var sigManifest artifactspec.Manifest
	err = json.Unmarshal(manifestJSON, &sigManifest)
	if err != nil {
		return &artifactspec.Manifest{}, err
	}
	return &sigManifest, nil
}

// uploadSignature uploads the signature envelope blob to the registry
func (c *repositoryClient) uploadSignature(ctx context.Context, blob []byte, mediaType string) (ocispec.Descriptor, error) {
	desc := ocispec.Descriptor{
		MediaType: mediaType,
		Digest:    digest.FromBytes(blob),
		Size:      int64(len(blob)),
	}
	if err := c.Repository.Blobs().Push(ctx, desc, bytes.NewReader(blob)); err != nil {
		return ocispec.Descriptor{}, err
	}
	return desc, nil
}

// uploadSignatureManifest uploads the signature manifest to the registry
func (c *repositoryClient) uploadSignatureManifest(ctx context.Context, subject, blobDesc ocispec.Descriptor, annotations map[string]string) (ocispec.Descriptor, error) {
	opts := oras.PackOptions{
		Subject:             &subject,
		ManifestAnnotations: annotations,
	}

	manifestDesc, err := oras.Pack(ctx, c.Repository.Manifests(), ArtifactTypeNotation, []ocispec.Descriptor{blobDesc}, opts)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	return manifestDesc, nil
}

func ociDescriptorFromArtifact(desc artifactspec.Descriptor) ocispec.Descriptor {
	return ocispec.Descriptor{
		MediaType: desc.MediaType,
		Digest:    desc.Digest,
		Size:      desc.Size,
	}
}
