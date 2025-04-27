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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/notaryproject/notation-go/internal/envelope"
	"github.com/notaryproject/notation-go/internal/mock/ocilayout"
	"github.com/notaryproject/notation-go/internal/slices"
	"github.com/notaryproject/notation-go/registry/internal/artifactspec"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
)

const (
	zeroDigest               = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	emptyConfigDigest        = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
	validDigest              = "6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b"
	validDigest2             = "1834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f2"
	invalidDigest            = "invaliddigest"
	algo                     = "sha256"
	validDigestWithAlgo      = algo + ":" + validDigest
	validDigestWithAlgo2     = algo + ":" + validDigest2
	validHost                = "localhost"
	validRegistry            = validHost + ":5000"
	invalidHost              = "badhost"
	invalidRegistry          = invalidHost + ":5000"
	validRepo                = "test"
	msg                      = "message"
	errMsg                   = "error message"
	validReference           = validRegistry + "/" + validRepo + "@" + validDigestWithAlgo
	referenceWithInvalidHost = invalidRegistry + "/" + validRepo + "@" + validDigestWithAlgo
	invalidReference         = "invalid reference"
	joseTag                  = "application/jose+json"
	coseTag                  = "application/cose"
	validTimestamp           = "2022-07-29T02:23:10Z"
	validPage                = `
	{
		"Manifests": [
			{	
				"MediaType": "application/vnd.oci.image.manifest.v1+json",
				"Digest": "sha256:cf2a0974295fc17b8351ef52abae2f40212e20e0359ea980ec5597bb0315347b",
				"Size": 620,
				"ArtifactType": "application/vnd.cncf.notary.signature"
			}
		]
	}`
	validPageDigest = "sha256:cf2a0974295fc17b8351ef52abae2f40212e20e0359ea980ec5597bb0315347b"
	validPageImage  = `
	{
		"Manifests": [
			{
				"MediaType": "application/vnd.oci.image.manifest.v1+json",
				"Digest": "sha256:c8f1c1a1bdf099fbc1b70ec4b98da3d8704e27d863f1407db06aad1e022a32cf",
				"Size": 733,
				"ArtifactType": "application/vnd.cncf.notary.signature"
			}
		]
	}`
	validPageImageDigest = "sha256:c8f1c1a1bdf099fbc1b70ec4b98da3d8704e27d863f1407db06aad1e022a32cf"
	validBlob            = `{
		"digest": "sha256:1834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f2",
		"size": 90
	}`
)

var (
	validDigestWithAlgoSlice = []string{validDigestWithAlgo, validDigestWithAlgo2}
	signaturePath            = filepath.FromSlash("../internal/testdata/jws_signature.sig")
)

type args struct {
	ctx                   context.Context
	reference             string
	remoteClient          remote.Client
	plainHttp             bool
	annotations           map[string]string
	subjectManifest       ocispec.Descriptor
	signature             []byte
	signatureMediaType    string
	signatureManifestDesc ocispec.Descriptor
	artifactManifestDesc  ocispec.Descriptor
}

type mockRemoteClient struct {
}

func (c mockRemoteClient) Do(req *http.Request) (*http.Response, error) {
	switch req.URL.Path {
	case "/v2/test/manifests/" + validDigest:
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader([]byte(msg))),
			Header: map[string][]string{
				"Content-Type":          {joseTag},
				"Docker-Content-Digest": {validDigestWithAlgo},
			},
		}, nil
	case "/v2/test/blobs/" + validDigestWithAlgo2:
		return &http.Response{
			StatusCode:    http.StatusOK,
			Body:          io.NopCloser(bytes.NewReader([]byte(validBlob))),
			ContentLength: maxBlobSizeLimit + 1,
			Header: map[string][]string{
				"Content-Type":          {joseTag},
				"Docker-Content-Digest": {validDigestWithAlgo2},
			},
		}, nil
	case "/v2/test/blobs/" + emptyConfigDigest:
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(bytes.NewReader([]byte{})),
		}, nil
	case "/v2/test/manifests/" + invalidDigest:
		return &http.Response{}, fmt.Errorf(errMsg)
	case "v2/test/manifest/" + validDigest2:
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader([]byte(validDigest2))),
			Header: map[string][]string{
				"Content-Type":          {joseTag},
				"Docker-Content-Digest": {validDigestWithAlgo2},
			},
		}, nil
	case "/v2/test/blobs/uploads/":
		switch req.Host {
		case validRegistry:
			return &http.Response{
				StatusCode: http.StatusAccepted,
				Body:       io.NopCloser(bytes.NewReader([]byte(msg))),
				Request: &http.Request{
					Header: map[string][]string{},
				},
				Header: map[string][]string{
					"Location": {"test"},
				},
			}, nil
		default:
			return &http.Response{}, fmt.Errorf(msg)
		}
	case "/v2/test/referrers/":
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type": []string{ocispec.MediaTypeImageIndex},
			},
			Body: io.NopCloser(bytes.NewReader([]byte(validPage))),
			Request: &http.Request{
				Method: "GET",
				URL:    &url.URL{Path: "/v2/test/referrers/"},
			},
		}, nil
	case "/v2/test/referrers/" + validDigestWithAlgo:
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type": []string{ocispec.MediaTypeImageIndex},
			},
			Body: io.NopCloser(bytes.NewReader([]byte(validPage))),
			Request: &http.Request{
				Method: "GET",
				URL:    &url.URL{Path: "/v2/test/referrers/" + validDigestWithAlgo},
			},
		}, nil
	case "/v2/test/referrers/" + zeroDigest:
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type": []string{ocispec.MediaTypeImageIndex},
			},
			Body: io.NopCloser(bytes.NewReader([]byte(validPageImage))),
			Request: &http.Request{
				Method: "GET",
				URL:    &url.URL{Path: "/v2/test/referrers/" + zeroDigest},
			},
		}, nil
	case validRepo:
		return &http.Response{
			StatusCode: http.StatusCreated,
			Body:       io.NopCloser(bytes.NewReader([]byte(msg))),
		}, nil
	default:
		_, digest, found := strings.Cut(req.URL.Path, "/v2/test/manifests/")
		if found && !slices.Contains(validDigestWithAlgoSlice, digest) {
			resp := &http.Response{
				StatusCode: http.StatusCreated,
				Body:       io.NopCloser(bytes.NewReader([]byte(msg))),
				Header: http.Header{
					"Content-Type": []string{joseTag},
					"Oci-Subject":  []string{validDigestWithAlgo},
				},
			}
			return resp, nil
		}
		return &http.Response{}, fmt.Errorf(errMsg)
	}
}

func TestResolve(t *testing.T) {
	tests := []struct {
		name      string
		args      args
		expect    ocispec.Descriptor
		expectErr bool
	}{
		{
			name: "failed to resolve",
			args: args{
				ctx:          context.Background(),
				reference:    invalidReference,
				remoteClient: mockRemoteClient{},
				plainHttp:    false,
			},
			expect:    ocispec.Descriptor{},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.args
			ref, _ := registry.ParseReference(args.reference)
			client := newRepositoryClient(args.remoteClient, ref, args.plainHttp)
			res, err := client.Resolve(args.ctx, args.reference)
			if (err != nil) != tt.expectErr {
				t.Errorf("error = %v, expectErr = %v", err, tt.expectErr)
			}
			if !reflect.DeepEqual(res, tt.expect) {
				t.Errorf("expect %+v, got %+v", tt.expect, res)
			}
		})
	}
}

func TestFetchSignatureBlob(t *testing.T) {
	tests := []struct {
		name      string
		args      args
		expect    []byte
		expectErr bool
	}{
		{
			name:      "failed to resolve",
			expect:    nil,
			expectErr: true,
			args: args{
				ctx:          context.Background(),
				reference:    validReference,
				remoteClient: mockRemoteClient{},
				plainHttp:    false,
				signatureManifestDesc: ocispec.Descriptor{
					MediaType: artifactspec.MediaTypeArtifactManifest,
					Digest:    digest.Digest(invalidDigest),
				},
			},
		},
		{
			name:      "exceed max blob size",
			expect:    nil,
			expectErr: true,
			args: args{
				ctx:          context.Background(),
				reference:    validReference,
				remoteClient: mockRemoteClient{},
				plainHttp:    false,
				signatureManifestDesc: ocispec.Descriptor{
					MediaType: artifactspec.MediaTypeArtifactManifest,
					Digest:    digest.Digest(validDigestWithAlgo2),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.args
			ref, _ := registry.ParseReference(args.reference)
			client := newRepositoryClient(args.remoteClient, ref, args.plainHttp)
			res, _, err := client.FetchSignatureBlob(args.ctx, args.signatureManifestDesc)
			if (err != nil) != tt.expectErr {
				t.Errorf("error = %v, expectErr = %v", err, tt.expectErr)
			}
			if !reflect.DeepEqual(res, tt.expect) {
				t.Errorf("expect %+v, got %+v", tt.expect, res)
			}
		})
	}
}

func TestListSignatures(t *testing.T) {
	tests := []struct {
		name      string
		args      args
		expect    []interface{}
		expectErr bool
	}{
		{
			name:      "successfully fetch content",
			expectErr: false,
			expect:    nil,
			args: args{
				ctx:          context.Background(),
				reference:    validReference,
				remoteClient: mockRemoteClient{},
				plainHttp:    false,
				artifactManifestDesc: ocispec.Descriptor{
					MediaType: "application/vnd.oci.image.manifest.v1+json",
					Digest:    validDigestWithAlgo,
					Size:      481,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.args
			ref, err := registry.ParseReference(args.reference)
			if err != nil {
				t.Fatal(err)
			}
			client := newRepositoryClient(args.remoteClient, ref, args.plainHttp)

			err = client.ListSignatures(args.ctx, args.artifactManifestDesc, func(signatureManifests []ocispec.Descriptor) error {
				if len(signatureManifests) != 1 {
					return fmt.Errorf("length of signatureManifests expected 1, got %d", len(signatureManifests))
				}
				for _, sigManifest := range signatureManifests {
					sigManifestDigest := sigManifest.Digest.String()
					if sigManifestDigest != validPageDigest {
						return fmt.Errorf("signature manifest digest expected: %s, got %s", validPageDigest, sigManifestDigest)
					}
				}
				return nil
			})
			if (err != nil) != tt.expectErr {
				t.Errorf("error = %v, expectErr = %v", err, tt.expectErr)
			}
		})
	}
}

func TestPushSignature(t *testing.T) {
	signature, err := os.ReadFile(signaturePath)
	if err != nil {
		t.Fatalf("failed to read signature: %v", err)
	}
	tests := []struct {
		name           string
		args           args
		expectDes      ocispec.Descriptor
		expectManifest ocispec.Descriptor
		expectErr      bool
	}{
		{
			name:      "failed to upload signature",
			expectErr: true,
			args: args{
				reference:          referenceWithInvalidHost,
				signatureMediaType: joseTag,
				signature:          signature,
				ctx:                context.Background(),
				remoteClient:       mockRemoteClient{},
			},
		},
		{
			name:      "successfully uploaded signature manifest",
			expectErr: false,
			args: args{
				reference:          validReference,
				signatureMediaType: joseTag,
				signature:          signature,
				ctx:                context.Background(),
				remoteClient:       mockRemoteClient{},
				subjectManifest: ocispec.Descriptor{
					MediaType: "application/vnd.oci.image.manifest.v1+json",
					Digest:    validDigestWithAlgo,
					Size:      481,
				},
				annotations: map[string]string{
					envelope.AnnotationX509ChainThumbprint: "[\"9f5f5aecee24b5cfdc7a91f6d5ac5c3a5348feb17c934d403f59ac251549ea0d\"]",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.args
			ref, _ := registry.ParseReference(args.reference)
			client := newRepositoryClient(args.remoteClient, ref, args.plainHttp)

			_, _, err := client.PushSignature(args.ctx, args.signatureMediaType, args.signature, args.subjectManifest, args.annotations)
			if (err != nil) != tt.expectErr {
				t.Errorf("error = %v, expectErr = %v", err, tt.expectErr)
			}
		})
	}
}

func TestPushSignatureImageManifest(t *testing.T) {
	ref, err := registry.ParseReference(validReference)
	if err != nil {
		t.Fatalf("failed to parse reference")
	}
	client := newRepositoryClientWithImageManifest(mockRemoteClient{}, ref, false)
	signature, err := os.ReadFile(signaturePath)
	if err != nil {
		t.Fatalf("failed to read signature: %v", err)
	}
	_, manifestDesc, err := client.PushSignature(context.Background(), joseTag, signature, ocispec.Descriptor{}, annotations)
	if err != nil {
		t.Fatalf("failed to push signature")
	}
	if manifestDesc.MediaType != ocispec.MediaTypeImageManifest {
		t.Errorf("expect manifestDesc.MediaType: %v, got %v", ocispec.MediaTypeImageManifest, manifestDesc.MediaType)
	}
}

// newRepositoryClient creates a new repository client
func newRepositoryClient(client remote.Client, ref registry.Reference, plainHTTP bool) *repositoryClient {
	repo := remote.Repository{
		Client:    client,
		Reference: ref,
		PlainHTTP: plainHTTP,
	}
	return &repositoryClient{
		GraphTarget: &repo,
	}
}

// newRepositoryClientWithImageManifest creates a new repository client for
// pushing OCI image manifest
func newRepositoryClientWithImageManifest(client remote.Client, ref registry.Reference, plainHTTP bool) *repositoryClient {
	return &repositoryClient{
		GraphTarget: &remote.Repository{
			Client:    client,
			Reference: ref,
			PlainHTTP: plainHTTP,
		},
	}
}

var (
	reference          = "sha256:19dbd2e48e921426ee8ace4dc892edfb2ecdc1d1a72d5416c83670c30acecef0"
	expectedTargetDesc = ocispec.Descriptor{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Digest:    "sha256:19dbd2e48e921426ee8ace4dc892edfb2ecdc1d1a72d5416c83670c30acecef0",
		Size:      481,
	}
	annotations = map[string]string{
		envelope.AnnotationX509ChainThumbprint: "[\"9f5f5aecee24b5cfdc7a91f6d5ac5c3a5348feb17c934d403f59ac251549ea0d\"]",
		ocispec.AnnotationCreated:              "2023-03-14T08:10:02Z",
	}
	expectedSignatureManifestDesc = ocispec.Descriptor{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Digest:    "sha256:64300ad03f1dcd18136787363f3069c9598623221cbe76e3233d35266b7973d6",
		Size:      793,
	}
	expectedSignatureBlobDesc = ocispec.Descriptor{
		MediaType: joseTag,
		Digest:    "sha256:586c5e0f341d7d07e835a06b7c9f21c21fff4f4a85933079e5859f99ba0ad02d",
		Size:      2078,
	}
)

func TestOciLayoutRepositoryPushAndFetch(t *testing.T) {
	// create a temp OCI layout
	ociLayoutTestdataPath, err := filepath.Abs(filepath.Join("..", "internal", "testdata", "oci-layout"))
	if err != nil {
		t.Fatalf("failed to get oci layout path: %v", err)
	}

	newOCILayoutPath := t.TempDir()
	if err := ocilayout.Copy(ociLayoutTestdataPath, newOCILayoutPath, "v2"); err != nil {
		t.Fatalf("failed to create temp oci layout: %v", err)
	}
	repo, err := NewOCIRepository(newOCILayoutPath, RepositoryOptions{})
	if err != nil {
		t.Fatalf("failed to create oci.Store as registry.Repository: %v", err)
	}

	// test resolve
	targetDesc, err := repo.Resolve(context.Background(), reference)
	if err != nil {
		t.Fatalf("failed to resolve reference: %v", err)
	}
	if !content.Equal(targetDesc, expectedTargetDesc) {
		t.Fatalf("failed to resolve reference. expected descriptor: %v, but got: %v", expectedTargetDesc, targetDesc)
	}

	t.Run("oci layout push", func(t *testing.T) {
		signature, err := os.ReadFile(signaturePath)
		if err != nil {
			t.Fatalf("failed to read signature: %v", err)
		}
		_, signatureManifestDesc, err := repo.PushSignature(context.Background(), joseTag, signature, targetDesc, annotations)
		if err != nil {
			t.Fatalf("failed to push signature: %v", err)
		}
		if !content.Equal(expectedSignatureManifestDesc, signatureManifestDesc) {
			t.Fatalf("expected desc: %v, got: %v", expectedSignatureManifestDesc, signatureManifestDesc)
		}
		expectedAnnotations := map[string]string{
			envelope.AnnotationX509ChainThumbprint: "[\"9f5f5aecee24b5cfdc7a91f6d5ac5c3a5348feb17c934d403f59ac251549ea0d\"]",
			ocispec.AnnotationCreated:              "2023-03-14T08:10:02Z",
		}
		if !reflect.DeepEqual(expectedAnnotations, signatureManifestDesc.Annotations) {
			t.Fatalf("expected annotations: %v, but got: %v", expectedAnnotations, signatureManifestDesc.Annotations)
		}
	})

	t.Run("oci layout fetch", func(t *testing.T) {
		err = repo.ListSignatures(context.Background(), targetDesc, func(signatureManifests []ocispec.Descriptor) error {
			if len(signatureManifests) == 0 {
				return fmt.Errorf("expected to find signature in the OCI layout folder, but got none")
			}
			var found bool
			for _, sigManifestDesc := range signatureManifests {
				if !content.Equal(sigManifestDesc, expectedSignatureManifestDesc) {
					continue
				}
				_, sigDesc, err := repo.FetchSignatureBlob(context.Background(), sigManifestDesc)
				if err != nil {
					return fmt.Errorf("failed to fetch blob: %w", err)
				}
				if !content.Equal(expectedSignatureBlobDesc, sigDesc) {
					return fmt.Errorf("expected to get signature blob desc: %v, got: %v", expectedSignatureBlobDesc, sigDesc)
				}
				found = true
			}
			if !found {
				return fmt.Errorf("expected to find the signature with manifest desc: %v, but failed", expectedSignatureManifestDesc)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestNewRepository(t *testing.T) {
	target, err := oci.New(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create oci.Store as registry.Repository: %v", err)
	}
	repo := NewRepository(target)
	if repo == nil {
		t.Fatalf("failed to create repository")
	}
	repoClient, ok := repo.(*repositoryClient)
	if !ok {
		t.Fatalf("failed to create repositoryClient")
	}
	if target != repoClient.GraphTarget {
		t.Fatalf("expected target: %v, got: %v", target, repoClient.GraphTarget)
	}
}

func TestNewOCIRepositoryFailed(t *testing.T) {
	t.Run("os stat failed", func(t *testing.T) {
		_, err := NewOCIRepository("invalid-path", RepositoryOptions{})
		if err == nil {
			t.Fatalf("expected to fail with invalid path")
		}
	})

	t.Run("path is regular file", func(t *testing.T) {
		// create a regular file in the temp dir
		filePath := filepath.Join(t.TempDir(), "file")
		file, err := os.Create(filePath)
		if err != nil {
			t.Fatalf("failed to create file: %v", err)
		}
		file.Close()

		_, err = NewOCIRepository(filePath, RepositoryOptions{})
		if err == nil {
			t.Fatalf("expected to fail with regular file")
		}
	})

	t.Run("no permission to create new path", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("skipping test on Windows")
		}
		// create a directory in the temp dir
		dirPath := filepath.Join(t.TempDir(), "dir")
		err := os.Mkdir(dirPath, 0000)
		if err != nil {
			t.Fatalf("failed to create dir: %v", err)
		}

		_, err = NewOCIRepository(dirPath, RepositoryOptions{})
		if err == nil {
			t.Fatalf("expected to fail with no permission to create new path")
		}
	})
}

// testStorage implements content.ReadOnlyGraphStorage
type testStorage struct {
	store             *memory.Store
	FetchError        error
	FetchContent      []byte
	PredecessorsError error
	PredecessorsDesc  []ocispec.Descriptor
}

func (s *testStorage) Push(ctx context.Context, expected ocispec.Descriptor, reader io.Reader) error {
	return s.store.Push(ctx, expected, reader)
}

func (s *testStorage) Fetch(ctx context.Context, target ocispec.Descriptor) (io.ReadCloser, error) {
	if s.FetchError != nil {
		return nil, s.FetchError
	}
	return io.NopCloser(bytes.NewReader(s.FetchContent)), nil
}

func (s *testStorage) Exists(ctx context.Context, target ocispec.Descriptor) (bool, error) {
	return s.store.Exists(ctx, target)
}

func (s *testStorage) Predecessors(ctx context.Context, node ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	if s.PredecessorsError != nil {
		return nil, s.PredecessorsError
	}
	return s.PredecessorsDesc, nil
}

func TestSignatureReferrers(t *testing.T) {
	t.Run("get predecessors failed", func(t *testing.T) {
		store := &testStorage{
			store:             &memory.Store{},
			PredecessorsError: fmt.Errorf("failed to get predecessors"),
		}
		_, err := signatureReferrers(context.Background(), store, ocispec.Descriptor{})
		if err == nil {
			t.Fatalf("expected to fail with getting predecessors")
		}
	})

	t.Run("artifact manifest exceds max blob size", func(t *testing.T) {
		store := &testStorage{
			store: &memory.Store{},
			PredecessorsDesc: []ocispec.Descriptor{
				{
					Digest:    validDigestWithAlgo2,
					MediaType: "application/vnd.oci.artifact.manifest.v1+json",
					Size:      4*1024*1024 + 1,
				},
			},
		}
		_, err := signatureReferrers(context.Background(), store, ocispec.Descriptor{
			Digest: validDigestWithAlgo2,
		})
		if err == nil {
			t.Fatalf("expected to fail with artifact manifest exceds max blob size")
		}
	})

	t.Run("image manifest exceds max blob size", func(t *testing.T) {
		store := &testStorage{
			store: &memory.Store{},
			PredecessorsDesc: []ocispec.Descriptor{
				{
					Digest:    validDigestWithAlgo2,
					MediaType: "application/vnd.oci.image.manifest.v1+json",
					Size:      4*1024*1024 + 1,
				},
			},
		}
		_, err := signatureReferrers(context.Background(), store, ocispec.Descriptor{
			Digest: validDigestWithAlgo2,
		})
		if err == nil {
			t.Fatalf("expected to fail with image manifest exceds max blob size")
		}
	})

	t.Run("artifact manifest fetchAll failed", func(t *testing.T) {
		store := &testStorage{
			store: &memory.Store{},
			PredecessorsDesc: []ocispec.Descriptor{
				{
					Digest:    validDigestWithAlgo,
					MediaType: "application/vnd.oci.artifact.manifest.v1+json",
					Size:      481,
				},
			},
			FetchError: fmt.Errorf("failed to fetch all"),
		}
		_, err := signatureReferrers(context.Background(), store, ocispec.Descriptor{
			Digest: validDigestWithAlgo,
		})
		if err == nil {
			t.Fatalf("expected to fail with fetchAll failed")
		}
	})

	t.Run("image manifest fetchAll failed", func(t *testing.T) {
		store := &testStorage{
			store: &memory.Store{},
			PredecessorsDesc: []ocispec.Descriptor{
				{
					Digest:    validDigestWithAlgo,
					MediaType: "application/vnd.oci.image.manifest.v1+json",
					Size:      481,
				},
			},
			FetchError: fmt.Errorf("failed to fetch all"),
		}
		_, err := signatureReferrers(context.Background(), store, ocispec.Descriptor{
			Digest: validDigestWithAlgo,
		})
		if err == nil {
			t.Fatalf("expected to fail with fetchAll failed")
		}
	})

	t.Run("artifact manifest marshal failed", func(t *testing.T) {
		store := &testStorage{
			store: &memory.Store{},
			PredecessorsDesc: []ocispec.Descriptor{
				{
					Digest:    "sha256:24aafc739daae02bcd33471a1b28bcfaaef0bb5e530ef44cd4e5d2445e606690",
					MediaType: "application/vnd.oci.artifact.manifest.v1+json",
					Size:      15,
				},
			},
			FetchContent: []byte("invalid content"),
		}
		_, err := signatureReferrers(context.Background(), store, ocispec.Descriptor{
			Digest: "sha256:24aafc739daae02bcd33471a1b28bcfaaef0bb5e530ef44cd4e5d2445e606690",
		})
		if err == nil {
			t.Fatalf("expected to fail with marshal failed")
		}
	})

	t.Run("image manifest marshal failed", func(t *testing.T) {
		store := &testStorage{
			store: &memory.Store{},
			PredecessorsDesc: []ocispec.Descriptor{
				{
					Digest:    "sha256:24aafc739daae02bcd33471a1b28bcfaaef0bb5e530ef44cd4e5d2445e606690",
					MediaType: "application/vnd.oci.image.manifest.v1+json",
					Size:      15,
				},
			},
			FetchContent: []byte("invalid content"),
		}
		_, err := signatureReferrers(context.Background(), store, ocispec.Descriptor{
			Digest: "sha256:24aafc739daae02bcd33471a1b28bcfaaef0bb5e530ef44cd4e5d2445e606690",
		})
		if err == nil {
			t.Fatalf("expected to fail with marshal failed")
		}
	})

	t.Run("no valid artifact manifest", func(t *testing.T) {
		store := &testStorage{
			store: &memory.Store{},
			PredecessorsDesc: []ocispec.Descriptor{
				{
					Digest:    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
					MediaType: "application/vnd.oci.artifact.manifest.v1+json",
					Size:      2,
				},
			},
			FetchContent: []byte("{}"),
		}
		descriptors, err := signatureReferrers(context.Background(), store, ocispec.Descriptor{
			Digest: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
		})

		if err != nil {
			t.Fatalf("failed to get referrers: %v", err)
		}
		if len(descriptors) != 0 {
			t.Fatalf("expected to get no referrers, but got: %v", descriptors)
		}
	})

	t.Run("no valid image manifest", func(t *testing.T) {
		store := &testStorage{
			store: &memory.Store{},
			PredecessorsDesc: []ocispec.Descriptor{
				{
					Digest:    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
					MediaType: "application/vnd.oci.image.manifest.v1+json",
					Size:      2,
				},
			},
			FetchContent: []byte("{}"),
		}
		descriptors, err := signatureReferrers(context.Background(), store, ocispec.Descriptor{
			Digest: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
		})

		if err != nil {
			t.Fatalf("failed to get referrers: %v", err)
		}
		if len(descriptors) != 0 {
			t.Fatalf("expected to get no referrers, but got: %v", descriptors)
		}
	})
}

func TestUploadSignatureManifest(t *testing.T) {
	ref, err := registry.ParseReference(validReference)
	if err != nil {
		t.Fatalf("failed to parse reference")
	}
	client := newRepositoryClientWithImageManifest(mockRemoteClient{}, ref, false)
	manifest, err := client.uploadSignatureManifest(context.Background(),
		ocispec.Descriptor{}, ocispec.Descriptor{}, nil)
	if err != nil {
		t.Fatalf("failed to upload signature manifest: %v", err)
	}
	if manifest.ArtifactType != ArtifactTypeNotation {
		t.Fatalf("expected artifact type: %s, got: %s", ArtifactTypeNotation, manifest.ArtifactType)
	}
}
