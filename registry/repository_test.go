package registry

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/notaryproject/notation-go"
	"github.com/opencontainers/go-digest"
	artifactspec "github.com/oras-project/artifacts-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
)

const (
	validDigest              = "6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b"
	validDigest2             = "9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0"
	validDigest3             = "1834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f2"
	validDigest4             = "277000f8d32d2b2a7d65f4533339f7d4c064e0540facf1d54c69d9916f05d28c"
	validDigest5             = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	validDigest6             = "daffbe5f71beaf7b05c080e8ae4f9739cdf21e24c89561e35792f1251d38148d"
	validDigest7             = "13b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	validDigest8             = "57f2c47061dae97063dc46598168a80a9f89302c1f24fe2a422a1ec0aba3017a"
	validDigest9             = "023c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b"
	validDigest10            = "1761e09cad8aa44e48ffb41c78371a6c139bd0df555c90b5d99739b9551c7828"
	invalidDigest            = "invaliddigest"
	algo                     = "sha256"
	validDigestWithAlgo      = algo + ":" + validDigest
	validDigestWithAlgo2     = algo + ":" + validDigest2
	validDigestWithAlgo3     = algo + ":" + validDigest3
	validDigestWithAlgo4     = algo + ":" + validDigest4
	validDigestWithAlgo5     = algo + ":" + validDigest5
	validDigestWithAlgo6     = algo + ":" + validDigest6
	validDigestWithAlgo7     = algo + ":" + validDigest7
	validDigestWithAlgo8     = algo + ":" + validDigest8
	validDigestWithAlgo9     = algo + ":" + validDigest9
	validDigestWithAlgo10    = algo + ":" + validDigest10
	validHost                = "localhost"
	validRegistry            = validHost + ":5000"
	invalidHost              = "badhost"
	invalidRegistry          = invalidHost + ":5000"
	validRepo                = "test"
	msg                      = "message"
	errMsg                   = "error message"
	mediaType                = "application/json"
	validReference           = validRegistry + "/" + validRepo + "@" + validDigest
	referenceWithInvalidHost = invalidRegistry + "/" + validRepo + "@" + validDigest
	validReference6          = validRegistry + "/" + validRepo + "@" + validDigest6
	invalidReference         = "invalid reference"
	joseTag                  = "application/jose+json"
	coseTag                  = "application/cose"
	validTimestamp           = "2022-07-29T02:23:10Z"
	size                     = 104
	size2                    = 135
	validPage                = `
	{
		"references": [{}],
		"referrers": [
			{
				"artifactType": "application/vnd.cncf.notary.v2.signature",
				"mediaType": "application/vnd.cncf.oras.artifact.manifest.v1+json",
				"digest": "localhost:5000/test@57f2c47061dae97063dc46598168a80a9f89302c1f24fe2a422a1ec0aba3017a"
			}
		]
	}`
	pageWithWrongMediaType = `
	{
		"references": [{}],
		"referrers": [
			{
				"artifactType": "application/vnd.cncf.notary.v2.signature",
				"mediaType": "application/vnd.cncf.oras.artifact.manifest.invalid",
				"digest": "localhost:5000/test@1834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f2"
			}
		]
	}`
	pageWithBadDigest = `
	{
		"references": [{}],
		"referrers": [
			{
				"artifactType": "application/vnd.cncf.notary.v2.signature",
				"mediaType": "application/vnd.cncf.oras.artifact.manifest.v1+json",
				"digest": "localhost:5000/test@9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0"
			}
		]
	}`
	validBlob = `{
		"digest": "sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b",
		"size": 90
	}`
	validManifest = `{
		"blobs": [
			{
				"digest": "sha256:023c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b",
				"size": 90
			}
		]
	}`
)

type args struct {
	ctx                context.Context
	reference          string
	remoteClient       remote.Client
	plainHttp          bool
	digest             digest.Digest
	annotations        map[string]string
	subjectManifest    notation.Descriptor
	signature          []byte
	signatureMediaType string
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
				"Content-Type":          {mediaType},
				"Docker-Content-Digest": {validDigestWithAlgo},
			},
		}, nil
	case "/v2/test/blobs/" + validDigestWithAlgo6:
		return &http.Response{
			StatusCode:    http.StatusOK,
			Body:          io.NopCloser(bytes.NewReader([]byte(validBlob))),
			ContentLength: size,
			Header: map[string][]string{
				"Content-Type":          {mediaType},
				"Docker-Content-Digest": {validDigestWithAlgo6},
			},
		}, nil
	case "/v2/test/blobs/" + validDigestWithAlgo3:
		return &http.Response{
			StatusCode:    http.StatusOK,
			Body:          io.NopCloser(bytes.NewReader([]byte(validBlob))),
			ContentLength: maxBlobSizeLimit + 1,
			Header: map[string][]string{
				"Content-Type":          {mediaType},
				"Docker-Content-Digest": {validDigestWithAlgo3},
			},
		}, nil
	case "/v2/test/manifests/" + invalidDigest:
		return &http.Response{}, fmt.Errorf(errMsg)
	case "/v2/test/_oras/artifacts/referrers":
		if strings.HasSuffix(req.URL.RawQuery, invalidDigest) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader([]byte(pageWithBadDigest))),
				Header: map[string][]string{
					"Oras-Api-Version": {"oras/1.1"},
				},
				Request: &http.Request{
					Method: "GET",
					URL:    &url.URL{Path: "/v2/test/_oras/artifacts/referrers"},
				},
			}, nil
		} else if strings.HasSuffix(req.URL.RawQuery, validDigest7) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader([]byte(pageWithWrongMediaType))),
				Header: map[string][]string{
					"Oras-Api-Version": {"oras/1.1"},
				},
				Request: &http.Request{
					Method: "GET",
					URL:    &url.URL{Path: "/v2/test/_oras/artifacts/referrers"},
				},
			}, nil
		} else if strings.HasSuffix(req.URL.RawQuery, validDigest8) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader([]byte(validPage))),
				Header: map[string][]string{
					"Oras-Api-Version": {"oras/1.1"},
				},
				Request: &http.Request{
					Method: "GET",
					URL:    &url.URL{Path: "/v2/test/_oras/artifacts/referrers"},
				},
			}, nil
		}
		return &http.Response{}, fmt.Errorf(msg)
	case "/v2/test/manifests/" + validDigest2:
		return &http.Response{
			StatusCode:    http.StatusOK,
			Body:          io.NopCloser(bytes.NewReader([]byte(validDigest2))),
			ContentLength: size,
			Header: map[string][]string{
				"Content-Type":          {mediaType},
				"Docker-Content-Digest": {validDigestWithAlgo4},
			},
		}, nil
	case "v2/test/manifest/" + validDigest3:
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader([]byte(validDigest3))),
			Header: map[string][]string{
				"Content-Type":          {mediaType},
				"Docker-Content-Digest": {validDigestWithAlgo3},
			},
		}, nil
	case "/v2/test/manifests/" + validDigest8:
		return &http.Response{
			StatusCode:    http.StatusOK,
			Body:          io.NopCloser(bytes.NewReader([]byte(validDigest8))),
			ContentLength: size2,
			Header: map[string][]string{
				"Content-Type":          {mediaType},
				"Docker-Content-Digest": {validDigestWithAlgo8},
			},
		}, nil
	case "/v2/test/manifests/" + validDigestWithAlgo4:
		if req.Method == "GET" {
			return &http.Response{}, fmt.Errorf(msg)
		}
		return &http.Response{
			StatusCode: http.StatusCreated,
			Body:       io.NopCloser(bytes.NewReader([]byte(msg))),
			Header: map[string][]string{
				"Docker-Content-Digest": {validDigestWithAlgo4},
			},
		}, nil
	case "/v2/test/manifests/" + validDigestWithAlgo7:
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader([]byte(msg))),
			Header: map[string][]string{
				"Docker-Content-Digest": {validDigestWithAlgo4},
			},
		}, nil
	case "/v2/test/manifests/" + validDigestWithAlgo8:
		return &http.Response{
			StatusCode:    http.StatusOK,
			Body:          io.NopCloser(bytes.NewReader([]byte(validManifest))),
			ContentLength: size2,
			Header: map[string][]string{
				"Docker-Content-Digest": {validDigestWithAlgo8},
				"Content-Type":          {mediaType},
			},
		}, nil
	case "/v2/test/manifests/" + validDigestWithAlgo2:
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader([]byte(validBlob))),
			Header: map[string][]string{
				"Docker-Content-Digest": {validDigestWithAlgo2},
				"Content-Type":          {mediaType},
			},
		}, nil
	case "/v2/test/manifests/" + validDigestWithAlgo10:
		if req.Method == "GET" {
			return &http.Response{}, fmt.Errorf(msg)
		}
		return &http.Response{
			StatusCode: http.StatusCreated,
			Body:       io.NopCloser(bytes.NewReader([]byte(msg))),
			Header: map[string][]string{
				"Docker-Content-Digest": {validDigestWithAlgo10},
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
	case validRepo:
		return &http.Response{
			StatusCode: http.StatusCreated,
			Body:       io.NopCloser(bytes.NewReader([]byte(msg))),
		}, nil
	default:
		return &http.Response{}, fmt.Errorf(errMsg)
	}
}

func TestNewRepositoryClient_constructCorrectly(t *testing.T) {
	remoteClient := mockRemoteClient{}
	ref := registry.Reference{}
	plainHttp := false
	client := NewRepositoryClient(remoteClient, ref, plainHttp)

	if client.Client != remoteClient ||
		client.PlainHTTP != plainHttp ||
		client.Reference != ref {
		t.Fatalf("Expect client with remoteClient: %v, plainHTTP: %v, ref: %v, got: %+v",
			remoteClient, plainHttp, ref, client.Client)
	}
}

func TestResolve(t *testing.T) {
	tests := []struct {
		name      string
		args      args
		expect    notation.Descriptor
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
			expect:    notation.Descriptor{},
			expectErr: true,
		},
		{
			name: "succeed to resolve",
			args: args{
				ctx:          context.Background(),
				reference:    validReference,
				remoteClient: mockRemoteClient{},
				plainHttp:    false,
			},
			expect: notation.Descriptor{
				MediaType: mediaType,
				Digest:    validDigestWithAlgo,
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.args
			ref, _ := registry.ParseReference(args.reference)
			client := NewRepositoryClient(args.remoteClient, ref, args.plainHttp)
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

func TestGetBlob(t *testing.T) {
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
				digest:       digest.Digest(invalidDigest),
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
				digest:       digest.Digest(validDigestWithAlgo3),
			},
		},
		{
			name:      "succeed to get",
			expect:    []byte(validBlob),
			expectErr: false,
			args: args{
				ctx:          context.Background(),
				reference:    validReference6,
				remoteClient: mockRemoteClient{},
				plainHttp:    false,
				digest:       digest.Digest(validDigestWithAlgo6),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.args
			ref, _ := registry.ParseReference(args.reference)
			client := NewRepositoryClient(args.remoteClient, ref, args.plainHttp)
			res, err := client.GetBlob(args.ctx, args.digest)
			if (err != nil) != tt.expectErr {
				t.Errorf("error = %v, expectErr = %v", err, tt.expectErr)
			}
			if !reflect.DeepEqual(res, tt.expect) {
				t.Errorf("expect %+v, got %+v", tt.expect, res)
			}
		})
	}
}

func TestListSignatureManifests(t *testing.T) {
	tests := []struct {
		name      string
		args      args
		expect    []SignatureManifest
		expectErr bool
	}{
		{
			name:      "wrong mediaType",
			expectErr: false,
			expect:    nil,
			args: args{
				ctx:          context.Background(),
				reference:    validReference,
				remoteClient: mockRemoteClient{},
				plainHttp:    false,
				digest:       digest.Digest(validDigest7),
			},
		},
		{
			name:      "failed to fetch content",
			expectErr: true,
			expect:    nil,
			args: args{
				ctx:          context.Background(),
				reference:    validReference,
				remoteClient: mockRemoteClient{},
				plainHttp:    false,
				digest:       digest.Digest(invalidDigest),
			},
		},
		{
			name:      "succeed to list",
			expectErr: false,
			expect: []SignatureManifest{
				{
					Blob: notation.Descriptor{
						Digest: validDigestWithAlgo9,
						Size:   90,
					},
				},
			},
			args: args{
				ctx:          context.Background(),
				reference:    validReference,
				remoteClient: mockRemoteClient{},
				plainHttp:    false,
				digest:       digest.Digest(validDigest8),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.args
			ref, _ := registry.ParseReference(args.reference)
			client := NewRepositoryClient(args.remoteClient, ref, args.plainHttp)

			res, err := client.ListSignatureManifests(args.ctx, args.digest)
			if (err != nil) != tt.expectErr {
				t.Errorf("error = %v, expectErr = %v", err, tt.expectErr)
			}
			if !reflect.DeepEqual(res, tt.expect) {
				t.Errorf("expect %+v, got %+v", tt.expect, res)
			}
		})
	}
}

func TestPutSignatureManifest(t *testing.T) {
	tests := []struct {
		name           string
		args           args
		expectDes      notation.Descriptor
		expectManifest SignatureManifest
		expectErr      bool
	}{
		{
			name:           "failed to upload signature",
			expectErr:      true,
			expectDes:      notation.Descriptor{},
			expectManifest: SignatureManifest{},
			args: args{
				reference:    referenceWithInvalidHost,
				signature:    make([]byte, 0),
				ctx:          context.Background(),
				remoteClient: mockRemoteClient{},
			},
		},
		{
			name:           "failed to upload signature manifest",
			expectErr:      true,
			expectDes:      notation.Descriptor{},
			expectManifest: SignatureManifest{},
			args: args{
				reference:    validReference,
				signature:    make([]byte, 0),
				ctx:          context.Background(),
				remoteClient: mockRemoteClient{},
			},
		},
		{
			name:      "succeed to put signature manifest with jws media type",
			expectErr: false,
			expectDes: notation.Descriptor{
				MediaType: artifactspec.MediaTypeArtifactManifest,
				Digest:    digest.Digest(validDigestWithAlgo4),
				Size:      369,
			},
			expectManifest: SignatureManifest{
				Annotations: map[string]string{
					artifactspec.AnnotationArtifactCreated: validTimestamp,
				},
				Blob: notation.Descriptor{
					MediaType: joseTag,
					Digest:    validDigestWithAlgo5,
				},
			},
			args: args{
				reference:    validReference,
				signature:    make([]byte, 0),
				ctx:          context.Background(),
				remoteClient: mockRemoteClient{},
				annotations: map[string]string{
					artifactspec.AnnotationArtifactCreated: validTimestamp,
				},
				signatureMediaType: joseTag,
			},
		},
		{
			name:      "succeed to put signature manifest with cose media type",
			expectErr: false,
			expectDes: notation.Descriptor{
				MediaType: artifactspec.MediaTypeArtifactManifest,
				Digest:    digest.Digest(validDigestWithAlgo10),
				Size:      364,
			},
			expectManifest: SignatureManifest{
				Annotations: map[string]string{
					artifactspec.AnnotationArtifactCreated: validTimestamp,
				},
				Blob: notation.Descriptor{
					MediaType: coseTag,
					Digest:    validDigestWithAlgo5,
				},
			},
			args: args{
				reference:    validReference,
				signature:    make([]byte, 0),
				ctx:          context.Background(),
				remoteClient: mockRemoteClient{},
				annotations: map[string]string{
					artifactspec.AnnotationArtifactCreated: validTimestamp,
				},
				signatureMediaType: coseTag,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.args
			ref, _ := registry.ParseReference(args.reference)
			client := NewRepositoryClient(args.remoteClient, ref, args.plainHttp)

			des, manifest, err := client.PutSignatureManifest(args.ctx, args.signature, args.signatureMediaType, args.subjectManifest, args.annotations)
			if (err != nil) != tt.expectErr {
				t.Errorf("error = %v, expectErr = %v", err, tt.expectErr)
			}
			if !reflect.DeepEqual(des, tt.expectDes) {
				t.Errorf("expect descriptor: %+v, got %+v", tt.expectDes, des)
			}
			if !reflect.DeepEqual(manifest, tt.expectManifest) {
				t.Errorf("expect manifest: %+v, got %+v", tt.expectManifest, manifest)
			}
		})
	}
}
