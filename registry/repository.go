// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/notaryproject/notation-go/registry/internal/artifactspec"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry"
)

const (
	maxBlobSizeLimit     = 32 * 1024 * 1024 // 32 MiB
	maxManifestSizeLimit = 4 * 1024 * 1024  // 4 MiB
)

// RepositoryOptions provides user options when creating a Repository
// it is kept for future extensibility
type RepositoryOptions struct{}

// repositoryClient implements Repository
type repositoryClient struct {
	oras.GraphTarget
	RepositoryOptions
}

// NewRepository returns a new Repository.
// Known implementations of oras.GraphTarget:
// - [remote.Repository](https://pkg.go.dev/oras.land/oras-go/v2/registry/remote#Repository)
// - [oci.Store](https://pkg.go.dev/oras.land/oras-go/v2/content/oci#Store)
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
	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCI store: %w", err)
	}
	if !fileInfo.IsDir() {
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
// target artifact's manifest descriptor
func (c *repositoryClient) ListSignatures(ctx context.Context, desc ocispec.Descriptor, fn func(signatureManifests []ocispec.Descriptor) error) error {
	if repo, ok := c.GraphTarget.(registry.ReferrerLister); ok {
		return repo.Referrers(ctx, desc, ArtifactTypeNotation, fn)
	}

	signatureManifests, err := signatureReferrers(ctx, c.GraphTarget, desc)
	if err != nil {
		return fmt.Errorf("failed to get referrers during ListSignatures due to %w", err)
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
	if sigManifestDesc.MediaType != artifactspec.MediaTypeArtifactManifest && sigManifestDesc.MediaType != ocispec.MediaTypeImageManifest {
		return ocispec.Descriptor{}, fmt.Errorf("sigManifestDesc.MediaType requires %q or %q, got %q", artifactspec.MediaTypeArtifactManifest, ocispec.MediaTypeImageManifest, sigManifestDesc.MediaType)
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
		var sigManifest artifactspec.Artifact
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
	configDesc, err := pushNotationManifestConfig(ctx, c.GraphTarget)
	if err != nil {
		return ocispec.Descriptor{}, err
	}

	opts := oras.PackManifestOptions{
		Subject:             &subject,
		ManifestAnnotations: annotations,
		Layers:              []ocispec.Descriptor{blobDesc},
		ConfigDescriptor:    configDesc,
	}

	return oras.PackManifest(ctx, c.GraphTarget, oras.PackManifestVersion1_1_RC4, "", opts)
}

// pushNotationManifestConfig pushes an empty notation manifest config, if it
// doesn't exist.
func pushNotationManifestConfig(ctx context.Context, pusher content.Pusher) (*ocispec.Descriptor, error) {
	// generate a empty config descriptor for notation manifest
	configContent := []byte("{}")
	desc := content.NewDescriptorFromBytes(ArtifactTypeNotation, configContent)

	// check if the config exists
	if ros, ok := pusher.(content.ReadOnlyStorage); ok {
		exists, err := ros.Exists(ctx, desc)
		if err != nil {
			return nil, fmt.Errorf("failed to check existence: %s: %s: %w", desc.Digest.String(), desc.MediaType, err)
		}
		if exists {
			return &desc, nil
		}
	}

	// push the config
	if err := pusher.Push(ctx, desc, bytes.NewReader(configContent)); err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
		return nil, fmt.Errorf("failed to push: %s: %s: %w", desc.Digest.String(), desc.MediaType, err)
	}
	return &desc, nil
}

// signatureReferrers returns referrer nodes of desc in target filtered by
// the "application/vnd.cncf.notary.signature" artifact type
func signatureReferrers(ctx context.Context, target content.ReadOnlyGraphStorage, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	var results []ocispec.Descriptor
	predecessors, err := target.Predecessors(ctx, desc)
	if err != nil {
		return nil, err
	}
	for _, node := range predecessors {
		switch node.MediaType {
		case artifactspec.MediaTypeArtifactManifest:
			if node.Size > maxManifestSizeLimit {
				return nil, fmt.Errorf("referrer node too large: %d bytes", node.Size)
			}
			fetched, err := content.FetchAll(ctx, target, node)
			if err != nil {
				return nil, err
			}
			var artifact artifactspec.Artifact
			if err := json.Unmarshal(fetched, &artifact); err != nil {
				return nil, err
			}
			if artifact.Subject == nil || !content.Equal(*artifact.Subject, desc) {
				continue
			}
			node.ArtifactType = artifact.ArtifactType
			node.Annotations = artifact.Annotations
		case ocispec.MediaTypeImageManifest:
			if node.Size > maxManifestSizeLimit {
				return nil, fmt.Errorf("referrer node too large: %d bytes", node.Size)
			}
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
