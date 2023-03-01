package registry

import (
	"context"
	"encoding/json"
	"fmt"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/registry/remote"
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
	oras.Target
	RepositoryOptions
}

// NewRepository returns a new Repository
func NewRepository(target oras.Target) Repository {
	return &repositoryClient{
		Target: target,
	}
}

// NewRepositoryWithOptions returns a new Repository with user specified
// options.
func NewRepositoryWithOptions(target oras.Target, opts RepositoryOptions) Repository {
	return &repositoryClient{
		Target:            target,
		RepositoryOptions: opts,
	}
}

// Resolve resolves a reference(tag or digest) to a manifest descriptor
func (c *repositoryClient) Resolve(ctx context.Context, reference string) (ocispec.Descriptor, error) {
	switch t := c.Target.(type) {
	case *remote.Repository:
		return t.Manifests().Resolve(ctx, reference)
	case *oci.Store:
		return t.Resolve(ctx, reference)
	default:
		return ocispec.Descriptor{}, fmt.Errorf("repositoryClient target type %T is not supported", t)
	}
}

// ListSignatures returns signature manifests filtered by fn given the
// artifact manifest descriptor
func (c *repositoryClient) ListSignatures(ctx context.Context, desc ocispec.Descriptor, fn func(signatureManifests []ocispec.Descriptor) error) error {
	switch t := c.Target.(type) {
	case *remote.Repository:
		return t.Referrers(ctx, desc, ArtifactTypeNotation, fn)
	case *oci.Store:
		predecessors, err := t.Predecessors(ctx, desc)
		if err != nil {
			return fmt.Errorf("failed to get predecessors during ListSignatures due to %w", err)
		}
		var signatureManifests []ocispec.Descriptor
		for _, manifest := range predecessors {
			if manifest.ArtifactType == ArtifactTypeNotation {
				signatureManifests = append(signatureManifests, manifest)
			}
		}
		return fn(signatureManifests)
	default:
		return fmt.Errorf("repositoryClient target type %T is not supported", t)
	}
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

	var sigBlob []byte
	switch t := c.Target.(type) {
	case *remote.Repository:
		sigBlob, err = content.FetchAll(ctx, t.Blobs(), sigBlobDesc)
		if err != nil {
			return nil, ocispec.Descriptor{}, err
		}
	case *oci.Store:
		sigBlob, err = content.FetchAll(ctx, t, sigBlobDesc)
		if err != nil {
			return nil, ocispec.Descriptor{}, err
		}
	default:
		return nil, ocispec.Descriptor{}, fmt.Errorf("repositoryClient target type %T is not supported", t)
	}
	return sigBlob, sigBlobDesc, nil
}

// PushSignature creates and uploads an signature manifest along with its
// linked signature envelope blob. Upon successful, PushSignature returns
// signature envelope blob and manifest descriptors.
func (c *repositoryClient) PushSignature(ctx context.Context, mediaType string, blob []byte, subject ocispec.Descriptor, annotations map[string]string) (blobDesc, manifestDesc ocispec.Descriptor, err error) {
	switch t := c.Target.(type) {
	case *remote.Repository:
		blobDesc, err = oras.PushBytes(ctx, t.Blobs(), mediaType, blob)
		if err != nil {
			return ocispec.Descriptor{}, ocispec.Descriptor{}, err
		}
	case *oci.Store:
		blobDesc, err = oras.PushBytes(ctx, t, mediaType, blob)
		if err != nil {
			return ocispec.Descriptor{}, ocispec.Descriptor{}, err
		}
	default:
		return ocispec.Descriptor{}, ocispec.Descriptor{}, fmt.Errorf("repositoryClient target type %T is not supported", t)
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
	var manifestJSON []byte
	var err error
	switch t := c.Target.(type) {
	case *remote.Repository:
		manifestJSON, err = content.FetchAll(ctx, t.Manifests(), sigManifestDesc)
		if err != nil {
			return ocispec.Descriptor{}, err
		}
	case *oci.Store:
		manifestJSON, err = content.FetchAll(ctx, t, sigManifestDesc)
		if err != nil {
			return ocispec.Descriptor{}, err
		}
	default:
		return ocispec.Descriptor{}, fmt.Errorf("repositoryClient target type %T is not supported", t)
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

	switch t := c.Target.(type) {
	case *remote.Repository, *oci.Store:
		return oras.Pack(ctx, t, ArtifactTypeNotation, []ocispec.Descriptor{blobDesc}, opts)
	default:
		return ocispec.Descriptor{}, fmt.Errorf("repositoryClient target type %T is not supported", t)
	}
}
