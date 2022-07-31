package mock

import _ "embed"

import (
	"context"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/plugin"
	"github.com/notaryproject/notation-go/plugin/manager"
	"github.com/notaryproject/notation-go/registry"
	"github.com/opencontainers/go-digest"
)

//go:embed testdata/ca_valid_sig_env.json
var MockCaValidSigEnv []byte

//go:embed testdata/ca_invalid_sig_env.json
var MockCaInvalidSigEnv []byte

//go:embed testdata/sa_valid_sig_env.json
var MockSaValidSigEnv []byte

//go:embed testdata/sa_invalid_sig_env.json
var MockSaInvalidSigEnv []byte

//go:embed testdata/ca_expired_sig_env.json
var MockCaExpiredSigEnv []byte

//go:embed testdata/sa_expired_sig_env.json
var MockSaExpiredSigEnv []byte

var (
	SampleArtifactUri   = "registry.acme-rockets.io/software/net-monitor@sha256:73c803930ea3ba1e54bc25c2bdc53edd0284c62ed651fe7b00369da519a3c333"
	SampleDigest        = digest.FromString("sha256:73c803930ea3ba1e54bc25c2bdc53edd0284c62ed651fe7b00369da519a3c333")
	Annotations         = map[string]string{"key": "value"}
	JwsSigEnvDescriptor = notation.Descriptor{
		MediaType:   "application/jose+json",
		Digest:      SampleDigest,
		Size:        100,
		Annotations: Annotations,
	}
)

type Repository struct {
	ResolveResponse                notation.Descriptor
	ResolveError                   error
	ListSignatureManifestsResponse []registry.SignatureManifest
	ListSignatureManifestsError    error
	GetResponse                    []byte
	GetError                       error
}

func NewRepository() Repository {
	return Repository{
		ResolveResponse: JwsSigEnvDescriptor,
		ListSignatureManifestsResponse: []registry.SignatureManifest{{
			Blob:        JwsSigEnvDescriptor,
			Annotations: Annotations,
		}},
		GetResponse: MockCaValidSigEnv,
	}
}

func (t Repository) Resolve(ctx context.Context, reference string) (notation.Descriptor, error) {
	return t.ResolveResponse, t.ResolveError
}

func (t Repository) ListSignatureManifests(ctx context.Context, manifestDigest digest.Digest) ([]registry.SignatureManifest, error) {
	return t.ListSignatureManifestsResponse, t.ListSignatureManifestsError
}

func (t Repository) GetBlob(ctx context.Context, digest digest.Digest) ([]byte, error) {
	return t.GetResponse, t.GetError
}

func (t Repository) PutSignatureManifest(ctx context.Context, signature []byte, manifest notation.Descriptor, annotaions map[string]string) (notation.Descriptor, registry.SignatureManifest, error) {
	return notation.Descriptor{}, registry.SignatureManifest{}, nil
}

type PluginManager struct{}

func NewPluginManager() PluginManager {
	return PluginManager{}
}

func (t PluginManager) Get(ctx context.Context, name string) (*manager.Plugin, error) {
	return nil, nil
}
func (t PluginManager) Runner(name string) (plugin.Runner, error) {
	return nil, nil
}
