package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/registry"
)

const (
	maxBlobSizeLimit     = 32 * 1024 * 1024 // 32 MiB
	maxManifestSizeLimit = 4 * 1024 * 1024  // 4 MiB
)

// RepositoryOptions provides user options when creating a Repository
type RepositoryOptions struct {
	// OCIImageManifest specifies if user wants to use OCI image manifest
	// to store signatures in remote registries.
	// By default, Notation will use OCI artifact manifest to store signatures.
	// If OCIImageManifest flag is set to true, Notation will instead use
	// OCI image manifest.
	// Note, Notation will not automatically convert between these two types
	// on any occasion.
	// OCI artifact manifest: https://github.com/opencontainers/image-spec/blob/v1.1.0-rc2/artifact.md
	// OCI image manifest: https://github.com/opencontainers/image-spec/blob/v1.1.0-rc2/manifest.md
	OCIImageManifest bool
}

// repositoryClient implements Repository
type repositoryClient struct {
	// oras.GraphTarget specifies the type of the target.
	// Implementations that are supported in Notation:
	// remote.Repository (https://pkg.go.dev/oras.land/oras-go/v2@v2.0.1/registry/remote#Repository)
	// oci.Store (https://pkg.go.dev/oras.land/oras-go/v2@v2.0.1/content/oci#Store)
	oras.GraphTarget
	RepositoryOptions
}

// NewRepository returns a new Repository
func NewRepository(target oras.GraphTarget) Repository {
	return &repositoryClient{
		GraphTarget: target,
	}
}

// NewRepositoryWithOptions returns a new Repository with user specified
// options.
func NewRepositoryWithOptions(target oras.GraphTarget, opts RepositoryOptions) Repository {
	return &repositoryClient{
		GraphTarget:       target,
		RepositoryOptions: opts,
	}
}

// NewOCIRepository returns a new Repository with oci.Store as
// its oras.GraphTarget. `path` denotes directory path to the target OCI layout.
func NewOCIRepository(path string, opts RepositoryOptions) (Repository, error) {
	dir, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCI store: %w", err)
	}
	if !dir.IsDir() {
		return nil, fmt.Errorf("failed to create OCI store: the input path is not a directory")
	}
	ociStore, err := oci.New(path)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCI store: %w", err)
	}
	return NewRepositoryWithOptions(ociStore, opts), nil
}

// Resolve resolves a reference(tag or digest) to a manifest descriptor
func (c *repositoryClient) Resolve(ctx context.Context, reference string) (ocispec.Descriptor, error) {
	if repo, ok := c.GraphTarget.(registry.Repository); ok {
		return repo.Manifests().Resolve(ctx, reference)
	}
	return c.GraphTarget.Resolve(ctx, reference)
}

// ListSignatures returns signature manifests filtered by fn given the
// artifact manifest descriptor
func (c *repositoryClient) ListSignatures(ctx context.Context, desc ocispec.Descriptor, fn func(signatureManifests []ocispec.Descriptor) error) error {
	if repo, ok := c.GraphTarget.(registry.ReferrerLister); ok {
		return repo.Referrers(ctx, desc, ArtifactTypeNotation, fn)
	}

	signatureManifests, err := predecessors(ctx, c.GraphTarget, desc)
	if err != nil {
		return fmt.Errorf("failed to get predecessors during ListSignatures due to %w", err)
	}
	return fn(signatureManifests)
}

// FetchSignatureBlob returns signature envelope blob and descriptor given
// signature manifest descriptor
func (c *repositoryClient) FetchSignatureBlob(ctx context.Context, desc ocispec.Descriptor) ([]byte, ocispec.Descriptor, error) {
	sigBlobDesc, err := c.getSignatureBlobDesc(ctx, desc)
	if err != nil {
		return nil, ocispec.Descriptor{}, err
	}
	if sigBlobDesc.Size > maxBlobSizeLimit {
		return nil, ocispec.Descriptor{}, fmt.Errorf("signature blob too large: %d bytes", sigBlobDesc.Size)
	}

	var fetcher content.Fetcher = c.GraphTarget
	if repo, ok := c.GraphTarget.(registry.Repository); ok {
		fetcher = repo.Blobs()
	}
	sigBlob, err := content.FetchAll(ctx, fetcher, sigBlobDesc)
	if err != nil {
		return nil, ocispec.Descriptor{}, err
	}
	return sigBlob, sigBlobDesc, nil
}

// PushSignature creates and uploads an signature manifest along with its
// linked signature envelope blob. Upon successful, PushSignature returns
// signature envelope blob and manifest descriptors.
func (c *repositoryClient) PushSignature(ctx context.Context, mediaType string, blob []byte, subject ocispec.Descriptor, annotations map[string]string) (blobDesc, manifestDesc ocispec.Descriptor, err error) {
	var pusher content.Pusher = c.GraphTarget
	if repo, ok := c.GraphTarget.(registry.Repository); ok {
		pusher = repo.Blobs()
	}
	blobDesc, err = oras.PushBytes(ctx, pusher, mediaType, blob)
	if err != nil {
		return ocispec.Descriptor{}, ocispec.Descriptor{}, err
	}
	manifestDesc, err = c.uploadSignatureManifest(ctx, subject, blobDesc, annotations)
	if err != nil {
		return ocispec.Descriptor{}, ocispec.Descriptor{}, err
	}
	return blobDesc, manifestDesc, nil
}

// getSignatureBlobDesc returns signature blob descriptor from
// signature manifest blobs or layers given signature manifest descriptor
func (c *repositoryClient) getSignatureBlobDesc(ctx context.Context, sigManifestDesc ocispec.Descriptor) (ocispec.Descriptor, error) {
	if sigManifestDesc.MediaType != ocispec.MediaTypeArtifactManifest && sigManifestDesc.MediaType != ocispec.MediaTypeImageManifest {
		return ocispec.Descriptor{}, fmt.Errorf("sigManifestDesc.MediaType requires %q or %q, got %q", ocispec.MediaTypeArtifactManifest, ocispec.MediaTypeImageManifest, sigManifestDesc.MediaType)
	}
	if sigManifestDesc.Size > maxManifestSizeLimit {
		return ocispec.Descriptor{}, fmt.Errorf("signature manifest too large: %d bytes", sigManifestDesc.Size)
	}

	// get the signature manifest from sigManifestDesc
	var fetcher content.Fetcher = c.GraphTarget
	if repo, ok := c.GraphTarget.(registry.Repository); ok {
		fetcher = repo.Manifests()
	}
	manifestJSON, err := content.FetchAll(ctx, fetcher, sigManifestDesc)
	if err != nil {
		return ocispec.Descriptor{}, err
	}

	// get the signature blob descriptor from signature manifest
	var signatureBlobs []ocispec.Descriptor
	// OCI image manifest
	if sigManifestDesc.MediaType == ocispec.MediaTypeImageManifest {
		var sigManifest ocispec.Manifest
		if err := json.Unmarshal(manifestJSON, &sigManifest); err != nil {
			return ocispec.Descriptor{}, err
		}
		signatureBlobs = sigManifest.Layers
	} else { // OCI artifact manifest
		var sigManifest ocispec.Artifact
		if err := json.Unmarshal(manifestJSON, &sigManifest); err != nil {
			return ocispec.Descriptor{}, err
		}
		signatureBlobs = sigManifest.Blobs
	}

	if len(signatureBlobs) != 1 {
		return ocispec.Descriptor{}, fmt.Errorf("signature manifest requries exactly one signature envelope blob, got %d", len(signatureBlobs))
	}

	return signatureBlobs[0], nil
}

// uploadSignatureManifest uploads the signature manifest to the registry
func (c *repositoryClient) uploadSignatureManifest(ctx context.Context, subject, blobDesc ocispec.Descriptor, annotations map[string]string) (ocispec.Descriptor, error) {
	opts := oras.PackOptions{
		Subject:             &subject,
		ManifestAnnotations: annotations,
		PackImageManifest:   c.OCIImageManifest,
	}

	return oras.Pack(ctx, c.GraphTarget, ArtifactTypeNotation, []ocispec.Descriptor{blobDesc}, opts)
}

// predecessors returns predecessor nodes of desc in target and filter by artifactType
func predecessors(ctx context.Context, target content.ReadOnlyGraphStorage, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	var results []ocispec.Descriptor
	predecessors, err := target.Predecessors(ctx, desc)
	if err != nil {
		return nil, err
	}
	for _, node := range predecessors {
		switch node.MediaType {
		case ocispec.MediaTypeArtifactManifest:
			fetched, err := content.FetchAll(ctx, target, node)
			if err != nil {
				return nil, err
			}
			var artifact ocispec.Artifact
			if err := json.Unmarshal(fetched, &artifact); err != nil {
				return nil, err
			}
			if artifact.Subject == nil || !content.Equal(*artifact.Subject, desc) {
				continue
			}
			node.ArtifactType = artifact.ArtifactType
			node.Annotations = artifact.Annotations
		case ocispec.MediaTypeImageManifest:
			fetched, err := content.FetchAll(ctx, target, node)
			if err != nil {
				return nil, err
			}
			var image ocispec.Manifest
			if err := json.Unmarshal(fetched, &image); err != nil {
				return nil, err
			}
			if image.Subject == nil || !content.Equal(*image.Subject, desc) {
				continue
			}
			node.ArtifactType = image.Config.MediaType
			node.Annotations = image.Annotations
		default:
			continue
		}
		// only keep nodes of "application/vnd.cncf.notary.signature"
		if node.ArtifactType == ArtifactTypeNotation {
			results = append(results, node)
		}
	}
	return results, nil
}
