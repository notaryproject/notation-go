package mock

import (
	"context"
	_ "embed"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/internal/registry"
	"github.com/notaryproject/notation-go/plugin"
	"github.com/notaryproject/notation-go/plugin/manager"
	"github.com/opencontainers/go-digest"
)

//go:embed testdata/ca_valid_sig_env.json
var MockCaValidSigEnv []byte

//go:embed testdata/ca_invalid_sig_env.json
var MockCaInvalidSigEnv []byte

//go:embed testdata/sa_valid_sig_env.json
var MockSaValidSigEnv []byte

//go:embed testdata/ca_plugin_sig_env.json
var MockCaPluginSigEnv []byte // extended attributes are "SomeKey":"SomeValue", "io.cncf.notary.verificationPlugin":"plugin-name"

//go:embed testdata/sa_invalid_sig_env.json
var MockSaInvalidSigEnv []byte

//go:embed testdata/ca_expired_sig_env.json
var MockCaExpiredSigEnv []byte

//go:embed testdata/sa_expired_sig_env.json
var MockSaExpiredSigEnv []byte

//go:embed testdata/sa_plugin_sig_env.json
var MockSaPluginSigEnv []byte // extended attributes are "SomeKey":"SomeValue", "io.cncf.notary.verificationPlugin":"plugin-name"

var (
	SampleArtifactUri = "registry.acme-rockets.io/software/net-monitor@sha256:60043cf45eaebc4c0867fea485a039b598f52fd09fd5b07b0b2d2f88fad9d74e"
	SampleDigest      = digest.Digest("sha256:60043cf45eaebc4c0867fea485a039b598f52fd09fd5b07b0b2d2f88fad9d74e")
	Annotations       = map[string]string{"key": "value"}
	ImageDescriptor   = notation.Descriptor{
		MediaType:   "application/vnd.docker.distribution.manifest.v2+json",
		Digest:      SampleDigest,
		Size:        528,
		Annotations: nil,
	}
	JwsSigEnvDescriptor = notation.Descriptor{
		MediaType:   "application/jose+json",
		Digest:      SampleDigest,
		Size:        100,
		Annotations: Annotations,
	}
	PluginExtendedCriticalAttribute = signature.Attribute{
		Key:      "SomeKey",
		Critical: true,
		Value:    "SomeValue",
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
		ResolveResponse: ImageDescriptor,
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

func (t Repository) PutSignatureManifest(ctx context.Context, signature []byte, signatureMediaType string, manifest notation.Descriptor, annotaions map[string]string) (notation.Descriptor, registry.SignatureManifest, error) {
	return notation.Descriptor{}, registry.SignatureManifest{}, nil
}

type PluginManager struct {
	PluginCapabilities          []plugin.Capability
	GetPluginError              error
	PluginRunnerLoadError       error
	PluginRunnerExecuteResponse interface{}
	PluginRunnerExecuteError    error
}

type PluginRunner struct {
	Response interface{}
	Error    error
}

func (pr PluginRunner) Run(ctx context.Context, req plugin.Request) (interface{}, error) {
	return pr.Response, pr.Error
}

func (pm PluginManager) Get(ctx context.Context, name string) (*manager.Plugin, error) {
	return &manager.Plugin{
		Metadata: plugin.Metadata{
			Name:                      "plugin-name",
			Description:               "for mocking in unit tests",
			Version:                   "1.0.0",
			URL:                       ".",
			SupportedContractVersions: []string{"1.0"},
			Capabilities:              pm.PluginCapabilities,
		},
		Path: ".",
		Err:  nil,
	}, pm.GetPluginError
}
func (pm PluginManager) Runner(name string) (plugin.Runner, error) {
	return PluginRunner{
		Response: pm.PluginRunnerExecuteResponse,
		Error:    pm.PluginRunnerExecuteError,
	}, pm.PluginRunnerLoadError
}
