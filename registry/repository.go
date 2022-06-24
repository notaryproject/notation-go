package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/notaryproject/notation-go"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	artifactspec "github.com/oras-project/artifacts-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
)

const (
	maxBlobSizeLimit     = 32 * 1024 * 1024 // 32 MiB
	maxManifestSizeLimit = 4 * 1024 * 1024  // 4 MiB
)

type RepositoryClient struct {
	remote.Repository
}

type SignatureManifest struct {
	Blob        notation.Descriptor
	Annotations map[string]string
}

// NewRepositoryClient creates a new registry client.
func NewRepositoryClient(client remote.Client, ref registry.Reference, plainHTTP bool) *RepositoryClient {
	return &RepositoryClient{
		Repository: remote.Repository{
			Client:    client,
			Reference: ref,
			PlainHTTP: plainHTTP,
		},
	}
}

// Resolve resolves a reference(tag or digest) to a manifest descriptor
func (c *RepositoryClient) Resolve(ctx context.Context, reference string) (notation.Descriptor, error) {
	desc, err := c.Repository.Resolve(ctx, reference)
	if err != nil {
		return notation.Descriptor{}, err
	}
	return notationDescriptorFromOCI(desc), nil
}

// ListSignatureManifests returns all signature manifests given the manifest digest
func (c *RepositoryClient) ListSignatureManifests(ctx context.Context, manifestDigest digest.Digest) ([]SignatureManifest, error) {
	var signatureManifests []SignatureManifest
	// TODO(shizhMSFT): filter artifact type at the server side
	if err := c.Repository.Referrers(ctx, ocispec.Descriptor{
		Digest: manifestDigest,
	}, func(referrers []artifactspec.Descriptor) error {
		for _, desc := range referrers {
			if desc.ArtifactType != ArtifactTypeNotation || desc.MediaType != artifactspec.MediaTypeArtifactManifest {
				continue
			}
			artifact, err := c.getArtifactManifest(ctx, desc.Digest)
			if err != nil {
				return fmt.Errorf("failed to fetch manifest: %v: %v", desc.Digest, err)
			}
			if len(artifact.Blobs) == 0 {
				continue
			}
			signatureManifests = append(signatureManifests, SignatureManifest{
				Blob:        notationDescriptorFromArtifact(artifact.Blobs[0]),
				Annotations: artifact.Annotations,
			})
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return signatureManifests, nil
}

// Get downloads the content by the specified digest
func (c *RepositoryClient) Get(ctx context.Context, digest digest.Digest) ([]byte, error) {
	desc, err := c.Repository.Resolve(ctx, digest.String())
	if err != nil {
		return nil, err
	}
	if desc.Size > maxBlobSizeLimit {
		return nil, fmt.Errorf("signature blob too large: %d", desc.Size)
	}
	return content.FetchAll(ctx, c.Repository.Blobs(), desc)
}

// PutSignatureManifest creates and uploads an signature artifact linking the manifest and the signature
func (c *RepositoryClient) PutSignatureManifest(ctx context.Context, signature []byte, manifest notation.Descriptor, annotaions map[string]string) (notation.Descriptor, SignatureManifest, error) {
	signatureDesc, err := c.uploadSignature(ctx, signature)
	if err != nil {
		return notation.Descriptor{}, SignatureManifest{}, err
	}

	// generate artifact manifest
	artifactManifest := artifactspec.Manifest{
		MediaType:    artifactspec.MediaTypeArtifactManifest,
		ArtifactType: ArtifactTypeNotation,
		Blobs:        []artifactspec.Descriptor{signatureDesc},
		Subject:      artifactDescriptorFromNotation(manifest),
		Annotations:  annotaions,
	}
	signatureManifest := SignatureManifest{
		Blob:        notationDescriptorFromArtifact(signatureDesc),
		Annotations: annotaions,
	}

	manifestDesc, err := c.uploadSignatureManifest(ctx, artifactManifest)
	if err != nil {
		return notation.Descriptor{}, SignatureManifest{}, err
	}

	return manifestDesc, signatureManifest, nil
}

func (c *RepositoryClient) getArtifactManifest(ctx context.Context, manifestDigest digest.Digest) (artifactspec.Manifest, error) {
	repo := c.Repository
	repo.ManifestMediaTypes = []string{
		artifactspec.MediaTypeArtifactManifest,
	}
	store := repo.Manifests()
	desc, err := store.Resolve(ctx, manifestDigest.String())
	if err != nil {
		return artifactspec.Manifest{}, err
	}
	if desc.Size > maxManifestSizeLimit {
		return artifactspec.Manifest{}, fmt.Errorf("manifest too large: %d", desc.Size)
	}
	manifestJSON, err := content.FetchAll(ctx, store, desc)
	if err != nil {
		return artifactspec.Manifest{}, err
	}

	var manifest artifactspec.Manifest
	err = json.Unmarshal(manifestJSON, &manifest)
	if err != nil {
		return artifactspec.Manifest{}, err
	}
	return manifest, nil
}

// uploadSignature uploads the signature to the registry
func (c *RepositoryClient) uploadSignature(ctx context.Context, signature []byte) (artifactspec.Descriptor, error) {
	desc := ocispec.Descriptor{
		MediaType: MediaTypeNotationSignature,
		Digest:    digest.FromBytes(signature),
		Size:      int64(len(signature)),
	}
	if err := c.Repository.Blobs().Push(ctx, desc, bytes.NewReader(signature)); err != nil {
		return artifactspec.Descriptor{}, err
	}
	return artifactDescriptorFromOCI(desc), nil
}

// uploadSignatureManifest uploads the signature manifest to the registry
func (c *RepositoryClient) uploadSignatureManifest(ctx context.Context, manifest artifactspec.Manifest) (notation.Descriptor, error) {
	artifactJSON, err := json.Marshal(manifest)
	if err != nil {
		return notation.Descriptor{}, err
	}
	desc := ocispec.Descriptor{
		MediaType: artifactspec.MediaTypeArtifactManifest,
		Digest:    digest.FromBytes(artifactJSON),
		Size:      int64(len(artifactJSON)),
	}
	if err := c.Repository.Manifests().Push(ctx, desc, bytes.NewReader(artifactJSON)); err != nil {
		return notation.Descriptor{}, err
	}
	return notationDescriptorFromOCI(desc), nil
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
		MediaType: desc.MediaType,
		Digest:    desc.Digest,
		Size:      desc.Size,
	}
}

func artifactDescriptorFromOCI(desc ocispec.Descriptor) artifactspec.Descriptor {
	return artifactspec.Descriptor{
		MediaType: desc.MediaType,
		Digest:    desc.Digest,
		Size:      desc.Size,
	}
}

func notationDescriptorFromOCI(desc ocispec.Descriptor) notation.Descriptor {
	return notation.Descriptor{
		MediaType: desc.MediaType,
		Digest:    desc.Digest,
		Size:      desc.Size,
	}
}
