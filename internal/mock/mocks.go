package mock

import (
	"context"
	_ "embed"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go/internal/signatureManifest"
	"github.com/notaryproject/notation-go/plugin"
	"github.com/notaryproject/notation-go/plugin/manager"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
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
	ImageDescriptor   = ocispec.Descriptor{
		MediaType:   "application/vnd.docker.distribution.manifest.v2+json",
		Digest:      SampleDigest,
		Size:        528,
		Annotations: nil,
	}
	JwsSigEnvDescriptor = ocispec.Descriptor{
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
	ResolveResponse                ocispec.Descriptor
	ResolveError                   error
	ListSignatureManifestsResponse []signatureManifest.SignatureManifest
	ListSignatureManifestsError    error
	GetResponse                    []byte
	GetError                       error
}

func NewRepository() Repository {
	return Repository{
		ResolveResponse: ImageDescriptor,
		ListSignatureManifestsResponse: []signatureManifest.SignatureManifest{{
			Blob:        JwsSigEnvDescriptor,
			Annotations: Annotations,
		}},
		GetResponse: MockCaValidSigEnv,
	}
}

func (t Repository) Resolve(ctx context.Context, reference string) (ocispec.Descriptor, error) {
	return t.ResolveResponse, t.ResolveError
}

func (t Repository) ListSignatures(ctx context.Context, desc ocispec.Descriptor, fn func(signatureManifests []ocispec.Descriptor) error) error {
	return t.ListSignatureManifestsError
}

func (t Repository) FetchSignatureBlob(ctx context.Context, desc ocispec.Descriptor) ([]byte, ocispec.Descriptor, error) {
	return t.GetResponse, ocispec.Descriptor{}, t.GetError
}

func (t Repository) PushSignature(ctx context.Context, blob []byte, mediaType string, subject ocispec.Descriptor, annotations map[string]string) (blobDesc, manifestDesc ocispec.Descriptor, err error) {
	return ocispec.Descriptor{}, ocispec.Descriptor{}, nil
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
