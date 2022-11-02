package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/notaryproject/notation-go"
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

// Resolve resolves a reference(tag or digest) to a manifest descriptor
func (c *repositoryClient) Resolve(ctx context.Context, reference string) (notation.Descriptor, error) {
	desc, err := c.Repository.Resolve(ctx, reference)
	if err != nil {
		return notation.Descriptor{}, err
	}
	return notationDescriptorFromOCI(desc), nil
}

// ListSignatures returns signature manifests filtered by fn given the
// artifact manifest descriptor
func (c *repositoryClient) ListSignatures(ctx context.Context, desc notation.Descriptor, fn func(signatureManifests []notation.Descriptor) error) error {
	if err := c.Repository.Referrers(ctx, ocispec.Descriptor{
		Digest: desc.Digest,
	}, ArtifactTypeNotation, func(referrers []artifactspec.Descriptor) error {
		var sigManifestDesc []notation.Descriptor
		for _, referrer := range referrers {
			sigManifestDesc = append(sigManifestDesc, notationDescriptorFromArtifact(referrer))
		}
		return fn(sigManifestDesc)
	}); err != nil {
		return err
	}
	return nil
}

// FetchSignatureBlob returns signature envelope blob and descriptor given
// signature manifest descriptor
func (c *repositoryClient) FetchSignatureBlob(ctx context.Context, desc notation.Descriptor) ([]byte, notation.Descriptor, error) {
	sigManifest, err := c.getSignatureManifest(ctx, desc)
	if err != nil {
		return nil, notation.Descriptor{}, err
	}
	if len(sigManifest.Blobs) == 0 {
		return nil, notation.Descriptor{}, errors.New("signature manifest missing signature envelope blob")
	}
	ocidesc, err := c.Repository.Blobs().Resolve(ctx, sigManifest.Blobs[0].Digest.String())
	if err != nil {
		return nil, notation.Descriptor{}, err
	}
	if ocidesc.Size > maxBlobSizeLimit {
		return nil, notation.Descriptor{}, fmt.Errorf("signature blob too large: %d", ocidesc.Size)
	}
	sigBlob, err := content.FetchAll(ctx, c.Repository.Blobs(), ocidesc)
	if err != nil {
		return nil, notation.Descriptor{}, err
	}
	return sigBlob, notationDescriptorFromOCI(ocidesc), nil
}

// PushSignature creates and uploads an signature manifest along with its
// linked signature envelope blob. Upon successful, PushSignature returns
// signature envelope blob and manifest descriptors.
func (c *repositoryClient) PushSignature(ctx context.Context, blob []byte, mediaType string, subject notation.Descriptor, annotations map[string]string) (blobDesc, manifestDesc notation.Descriptor, err error) {
	blobDesc, err = c.uploadSignature(ctx, blob, mediaType)
	if err != nil {
		return notation.Descriptor{}, notation.Descriptor{}, err
	}

	manifestDesc, err = c.uploadSignatureManifest(ctx, artifactDescriptorFromNotation(subject), artifactDescriptorFromNotation(blobDesc), annotations)
	if err != nil {
		return notation.Descriptor{}, notation.Descriptor{}, err
	}

	return blobDesc, manifestDesc, nil
}

// getSignatureManifest returns signature manifest given signature manifest
// descriptor
func (c *repositoryClient) getSignatureManifest(ctx context.Context, sigManifestDesc notation.Descriptor) (artifactspec.Manifest, error) {

	repo := c.Repository
	repo.ManifestMediaTypes = []string{
		artifactspec.MediaTypeArtifactManifest,
	}
	store := repo.Manifests()
	ociDesc, err := store.Resolve(ctx, sigManifestDesc.Digest.String())
	if err != nil {
		return artifactspec.Manifest{}, err
	}
	if ociDesc.Size > maxManifestSizeLimit {
		return artifactspec.Manifest{}, fmt.Errorf("manifest too large: %d", ociDesc.Size)
	}
	manifestJSON, err := content.FetchAll(ctx, store, ociDesc)
	if err != nil {
		return artifactspec.Manifest{}, err
	}

	var sigManifest artifactspec.Manifest
	err = json.Unmarshal(manifestJSON, &sigManifest)
	if err != nil {
		return artifactspec.Manifest{}, err
	}
	return sigManifest, nil
}

// uploadSignature uploads the signature envelope blob to the registry
func (c *repositoryClient) uploadSignature(ctx context.Context, blob []byte, mediaType string) (notation.Descriptor, error) {
	desc := ocispec.Descriptor{
		MediaType: mediaType,
		Digest:    digest.FromBytes(blob),
		Size:      int64(len(blob)),
	}
	if err := c.Repository.Blobs().Push(ctx, desc, bytes.NewReader(blob)); err != nil {
		return notation.Descriptor{}, err
	}
	return notationDescriptorFromOCI(desc), nil
}

// uploadSignatureManifest uploads the signature manifest to the registry
func (c *repositoryClient) uploadSignatureManifest(ctx context.Context, subject, blobDesc artifactspec.Descriptor, annotations map[string]string) (notation.Descriptor, error) {
	opts := oras.PackArtifactOptions{
		Subject:             &subject,
		ManifestAnnotations: annotations,
	}

	manifestDesc, err := oras.PackArtifact(ctx, c.Repository.Manifests(), ArtifactTypeNotation, []artifactspec.Descriptor{blobDesc}, opts)
	if err != nil {
		return notation.Descriptor{}, err
	}
	return notationDescriptorFromOCI(manifestDesc), nil
}

func artifactDescriptorFromNotation(desc notation.Descriptor) artifactspec.Descriptor {
	return artifactspec.Descriptor{
		MediaType: desc.MediaType,
		Digest:    desc.Digest,
		Size:      desc.Size,
	}
}

func notationDescriptorFromArtifact(desc artifactspec.Descriptor) notation.Descriptor {
	return notation.Descriptor{
		MediaType:   desc.MediaType,
		Digest:      desc.Digest,
		Size:        desc.Size,
		Annotations: desc.Annotations,
	}
}

func notationDescriptorFromOCI(desc ocispec.Descriptor) notation.Descriptor {
	return notation.Descriptor{
		MediaType: desc.MediaType,
		Digest:    desc.Digest,
		Size:      desc.Size,
	}
}
