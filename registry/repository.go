package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/opencontainers/go-digest"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
	artifactspec "github.com/oras-project/artifacts-spec/specs-go/v1"
)

type repository struct {
	tr   http.RoundTripper
	base string
	name string
}

func (r *repository) Lookup(ctx context.Context, manifestDigest digest.Digest) ([]digest.Digest, error) {
	url, err := url.Parse(fmt.Sprintf("%s/oras/artifacts/v1/%s/manifests/%s/referrers", r.base, r.name, manifestDigest.String()))
	if err != nil {
		return nil, err
	}
	q := url.Query()
	q.Add("artifactType", ArtifactTypeNotation)
	url.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.tr.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to lookup signatures: %s", resp.Status)
	}

	result := struct {
		References []artifactspec.Descriptor `json:"references"`
	}{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxReadLimit)).Decode(&result); err != nil {
		return nil, err
	}
	digests := make([]digest.Digest, 0, len(result.References))
	for _, desc := range result.References {
		if desc.ArtifactType != ArtifactTypeNotation || desc.MediaType != artifactspec.MediaTypeArtifactManifest {
			continue
		}
		artifact, err := r.getArtifactManifest(ctx, desc.Digest)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch manifest: %v: %v", desc.Digest, err)
		}
		for _, blob := range artifact.Blobs {
			digests = append(digests, blob.Digest)
		}
	}
	return digests, nil
}

func (r *repository) Get(ctx context.Context, signatureDigest digest.Digest) ([]byte, error) {
	return r.getBlob(ctx, signatureDigest)
}

func (r *repository) Put(ctx context.Context, signature []byte) (oci.Descriptor, error) {
	desc := DescriptorFromBytes(signature)
	desc.MediaType = MediaTypeNotarySignature
	return desc, r.putBlob(ctx, signature, desc.Digest)
}

func (r *repository) Link(ctx context.Context, manifest, signature oci.Descriptor) (oci.Descriptor, error) {
	artifact := artifactspec.Manifest{
		MediaType:    artifactspec.MediaTypeArtifactManifest,
		ArtifactType: ArtifactTypeNotation,
		Blobs: []artifactspec.Descriptor{
			artifactDescriptorFromOCI(signature),
		},
		SubjectManifest: artifactDescriptorFromOCI(manifest),
	}
	artifactJSON, err := json.Marshal(artifact)
	if err != nil {
		return oci.Descriptor{}, err
	}
	desc := DescriptorFromBytes(artifactJSON)
	return desc, r.putManifest(ctx, artifactJSON, desc.Digest)
}

func (r *repository) getBlob(ctx context.Context, digest digest.Digest) ([]byte, error) {
	url := fmt.Sprintf("%s/v2/%s/blobs/%s", r.base, r.name, digest.String())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.tr.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return readAllVerified(resp.Body, digest)
	}
	if resp.StatusCode != http.StatusTemporaryRedirect {
		return nil, fmt.Errorf("failed to get blob: %s", resp.Status)
	}
	resp.Body.Close()

	location, err := resp.Location()
	if err != nil {
		return nil, err
	}
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, location.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err = r.tr.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get blob: %s", resp.Status)
	}
	return readAllVerified(resp.Body, digest)
}

func (r *repository) putBlob(ctx context.Context, blob []byte, digest digest.Digest) error {
	url := fmt.Sprintf("%s/v2/%s/blobs/uploads/", r.base, r.name)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	resp, err := r.tr.RoundTrip(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("failed to init upload: %s", resp.Status)
	}

	url = resp.Header.Get("Location")
	if url == "" {
		return http.ErrNoLocation
	}

	req, err = http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(blob))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	q := req.URL.Query()
	q.Add("digest", digest.String())
	req.URL.RawQuery = q.Encode()
	resp, err = r.tr.RoundTrip(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to upload: %s", resp.Status)
	}
	return nil
}

func (r *repository) putManifest(ctx context.Context, blob []byte, digest digest.Digest) error {
	url := fmt.Sprintf("%s/v2/%s/manifests/%s", r.base, r.name, digest.String())
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(blob))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", artifactspec.MediaTypeArtifactManifest)
	resp, err := r.tr.RoundTrip(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to put manifest: %s", resp.Status)
	}
	return nil
}

func (r *repository) getManifest(ctx context.Context, mediaType string, digest digest.Digest) ([]byte, error) {
	url := fmt.Sprintf("%s/v2/%s/manifests/%s", r.base, r.name, digest.String())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", mediaType)
	resp, err := r.tr.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get manifest: %s", resp.Status)
	}
	return readAllVerified(resp.Body, digest)
}

func (r *repository) getArtifactManifest(ctx context.Context, digest digest.Digest) (artifactspec.Manifest, error) {
	manifestJSON, err := r.getManifest(ctx, artifactspec.MediaTypeArtifactManifest, digest)
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

func artifactDescriptorFromOCI(desc oci.Descriptor) artifactspec.Descriptor {
	return artifactspec.Descriptor{
		MediaType: desc.MediaType,
		Digest:    desc.Digest,
		Size:      desc.Size,
	}
}
