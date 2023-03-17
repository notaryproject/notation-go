package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/notaryproject/notation-go/internal/envelope"
	"github.com/notaryproject/notation-go/log"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/registry"
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

// RepositoryClient implements Repository
type RepositoryClient struct {
	// oras.Target specifies the type of the target.
	// Implementations that are supported in Notation:
	// remote.Repository (https://pkg.go.dev/oras.land/oras-go/v2@v2.0.1/registry/remote#Repository)
	// oci.Store (https://pkg.go.dev/oras.land/oras-go/v2@v2.0.1/content/oci#Store)
	oras.Target
	RepositoryOptions
}

// NewRepository returns a new Repository
func NewRepository(target oras.Target) Repository {
	return &RepositoryClient{
		Target: target,
	}
}

// NewRepositoryWithOptions returns a new Repository with user specified
// options.
func NewRepositoryWithOptions(target oras.Target, opts RepositoryOptions) Repository {
	return &RepositoryClient{
		Target:            target,
		RepositoryOptions: opts,
	}
}

// NewRepositoryWithOciStore returns a new Repository with oci.Store as
// its oras.Target
func NewRepositoryWithOciStore(path string, opts RepositoryOptions) (Repository, error) {
	_, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCI store: %w", err)
	}
	ociStore, err := oci.New(path)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCI store: %w", err)
	}
	return NewRepositoryWithOptions(ociStore, opts), nil
}

// Resolve resolves a reference(tag or digest) to a manifest descriptor
func (c *RepositoryClient) Resolve(ctx context.Context, reference string) (ocispec.Descriptor, error) {
	logger := log.GetLogger(ctx)

	switch target := c.Target.(type) {
	case *remote.Repository:
		ref, err := registry.ParseReference(reference)
		if err != nil {
			return ocispec.Descriptor{}, err
		}
		if ref.Reference == "" {
			return ocispec.Descriptor{}, errors.New("reference is missing digest or tag")
		}
		targetDesc, err := target.Manifests().Resolve(ctx, reference)
		if err != nil {
			return ocispec.Descriptor{}, err
		}
		if ref.ValidateReferenceAsDigest() != nil {
			// artifactRef is not a digest reference
			logger.Warnf("Always sign the artifact using digest(`@sha256:...`) rather than a tag(`:%s`) because tags are mutable and a tag reference can point to a different artifact than the one signed", ref.Reference)
			logger.Infof("Resolved artifact tag `%s` to digest `%s` before signing", ref.Reference, targetDesc.Digest.String())
		}
		return targetDesc, nil
	case *oci.Store:
		targetDesc, err := target.Resolve(ctx, reference)
		if err != nil {
			return ocispec.Descriptor{}, err
		}
		if digest.Digest(reference).Validate() != nil {
			// ref is a tag
			logger.Warnf("Always sign the artifact using digest(`@sha256:...`) rather than a tag(`:%s`) because tags are mutable and a tag reference can point to a different artifact than the one signed", reference)
			logger.Infof("Resolved artifact tag `%s` to digest `%s` before signing", reference, targetDesc.Digest.String())
		}
		return targetDesc, nil
	default:
		return ocispec.Descriptor{}, fmt.Errorf("repositoryClient target type %T is not supported", target)
	}
}

// ListSignatures returns signature manifests filtered by fn given the
// artifact manifest descriptor
func (c *RepositoryClient) ListSignatures(ctx context.Context, desc ocispec.Descriptor, fn func(signatureManifests []ocispec.Descriptor) error) error {
	switch target := c.Target.(type) {
	case *remote.Repository:
		return target.Referrers(ctx, desc, ArtifactTypeNotation, fn)
	case *oci.Store:
		signatureManifests, err := referrers(ctx, target, desc, ArtifactTypeNotation)
		if err != nil {
			return fmt.Errorf("failed to get predecessors during ListSignatures due to %w", err)
		}
		return fn(signatureManifests)
	default:
		return fmt.Errorf("repositoryClient target type %T is not supported", target)
	}
}

// FetchSignatureBlob returns signature envelope blob and descriptor given
// signature manifest descriptor
func (c *RepositoryClient) FetchSignatureBlob(ctx context.Context, desc ocispec.Descriptor) ([]byte, ocispec.Descriptor, error) {
	sigBlobDesc, err := c.getSignatureBlobDesc(ctx, desc)
	if err != nil {
		return nil, ocispec.Descriptor{}, err
	}
	if sigBlobDesc.Size > maxBlobSizeLimit {
		return nil, ocispec.Descriptor{}, fmt.Errorf("signature blob too large: %d bytes", sigBlobDesc.Size)
	}

	var sigBlob []byte
	switch target := c.Target.(type) {
	case *remote.Repository:
		sigBlob, err = content.FetchAll(ctx, target.Blobs(), sigBlobDesc)
		if err != nil {
			return nil, ocispec.Descriptor{}, err
		}
	case *oci.Store:
		sigBlob, err = content.FetchAll(ctx, target, sigBlobDesc)
		if err != nil {
			return nil, ocispec.Descriptor{}, err
		}
	default:
		return nil, ocispec.Descriptor{}, fmt.Errorf("repositoryClient target type %T is not supported", target)
	}
	return sigBlob, sigBlobDesc, nil
}

// PushSignature creates and uploads an signature manifest along with its
// linked signature envelope blob. Upon successful, PushSignature returns
// signature envelope blob and manifest descriptors.
func (c *RepositoryClient) PushSignature(ctx context.Context, mediaType string, blob []byte, subject ocispec.Descriptor, annotations map[string]string) (blobDesc, manifestDesc ocispec.Descriptor, err error) {
	// sanity check
	if annotations == nil {
		return ocispec.Descriptor{}, ocispec.Descriptor{}, errors.New("pushing signature blob, but got nil annotations map")
	}
	if _, ok := annotations[envelope.AnnotationX509ChainThumbprint]; !ok {
		return ocispec.Descriptor{}, ocispec.Descriptor{}, fmt.Errorf("pushing signature blob, but annotations map missing field %q", envelope.AnnotationX509ChainThumbprint)
	}
	signingTime, err := envelope.SigningTime(blob, mediaType)
	if err != nil {
		return ocispec.Descriptor{}, ocispec.Descriptor{}, err
	}
	annotations[ocispec.AnnotationCreated] = signingTime.Format(time.RFC3339)
	switch target := c.Target.(type) {
	case *remote.Repository:
		blobDesc, err = oras.PushBytes(ctx, target.Blobs(), mediaType, blob)
		if err != nil {
			return ocispec.Descriptor{}, ocispec.Descriptor{}, err
		}
	case *oci.Store:
		blobDesc, err = oras.PushBytes(ctx, target, mediaType, blob)
		if err != nil {
			return ocispec.Descriptor{}, ocispec.Descriptor{}, err
		}
	default:
		return ocispec.Descriptor{}, ocispec.Descriptor{}, fmt.Errorf("repositoryClient target type %T is not supported", target)
	}
	manifestDesc, err = c.uploadSignatureManifest(ctx, subject, blobDesc, annotations)
	if err != nil {
		return ocispec.Descriptor{}, ocispec.Descriptor{}, err
	}

	return blobDesc, manifestDesc, nil
}

// getSignatureBlobDesc returns signature blob descriptor from
// signature manifest blobs or layers given signature manifest descriptor
func (c *RepositoryClient) getSignatureBlobDesc(ctx context.Context, sigManifestDesc ocispec.Descriptor) (ocispec.Descriptor, error) {
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
func (c *RepositoryClient) uploadSignatureManifest(ctx context.Context, subject, blobDesc ocispec.Descriptor, annotations map[string]string) (ocispec.Descriptor, error) {
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

// referrers returns referrer nodes of desc in target and filter by artifactType
func referrers(ctx context.Context, target content.ReadOnlyGraphStorage, desc ocispec.Descriptor, artifactType string) ([]ocispec.Descriptor, error) {
	var results []ocispec.Descriptor
	if repo, ok := target.(registry.ReferrerLister); ok {
		// get referrers directly
		err := repo.Referrers(ctx, desc, artifactType, func(referrers []ocispec.Descriptor) error {
			results = append(results, referrers...)
			return nil
		})
		if err != nil {
			return nil, err
		}
		return results, nil
	}

	// find matched referrers in all predecessors
	predecessors, err := target.Predecessors(ctx, desc)
	if err != nil {
		return nil, err
	}
	for _, node := range predecessors {
		switch node.MediaType {
		case ocispec.MediaTypeArtifactManifest:
			fetched, err := fetchBytes(ctx, target, node)
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
			fetched, err := fetchBytes(ctx, target, node)
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
		if node.ArtifactType != "" && (artifactType == "" || artifactType == node.ArtifactType) {
			results = append(results, node)
		}
	}
	return results, nil
}

// fetchBytes fetches the content described by the input descriptor
func fetchBytes(ctx context.Context, fetcher content.Fetcher, desc ocispec.Descriptor) ([]byte, error) {
	rc, err := fetcher.Fetch(ctx, desc)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return content.ReadAll(rc, desc)
}
