package mock

import (
	"context"
	_ "embed"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go/plugin"
	"github.com/notaryproject/notation-go/plugin/proto"
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

//go:embed testdata/sig_env_with_metadata.json
var MockSigEnvWithMetadata []byte

//go:embed testdata/ca_incompatible_pluginver_sig_env_1.0.9.json
var MockCaIncompatiblePluginVerSigEnv_1_0_9 []byte

//go:embed testdata/ca_incompatible_pluginver_sig_env_1.0.1.json
var MockCaIncompatiblePluginVerSigEnv_1_0_1 []byte

//go:embed testdata/ca_incompatible_pluginver_sig_env_1.2.3.json
var MockCaIncompatiblePluginVerSigEnv_1_2_3 []byte

//go:embed testdata/ca_incompatible_pluginver_sig_env_1.1.0-alpha.json
var MockCaIncompatiblePluginVerSigEnv_1_1_0_alpha []byte

//go:embed testdata/ca_compatible_pluginver_sig_env_0.0.9.json
var MockCaCompatiblePluginVerSigEnv_0_0_9 []byte

//go:embed testdata/ca_compatible_pluginver_sig_env_1.0.0-alpha.json
var MockCaCompatiblePluginVerSigEnv_1_0_0_alpha []byte

//go:embed testdata/ca_compatible_pluginver_sig_env_1.0.0-alpha.beta.json
var MockCaCompatiblePluginVerSigEnv_1_0_0_alpha_beta []byte

//go:embed testdata/ca_compatible_pluginver_sig_env_1.0.0.json
var MockCaCompatiblePluginVerSigEnv_1_0_0 []byte

var (
	SampleArtifactUri = "registry.acme-rockets.io/software/net-monitor@sha256:60043cf45eaebc4c0867fea485a039b598f52fd09fd5b07b0b2d2f88fad9d74e"
	SampleDigest      = digest.Digest("sha256:60043cf45eaebc4c0867fea485a039b598f52fd09fd5b07b0b2d2f88fad9d74e")
	Annotations       = map[string]string{"key": "value"}
	ImageDescriptor   = ocispec.Descriptor{
		MediaType:   "application/vnd.docker.distribution.manifest.v2+json",
		Digest:      SampleDigest,
		Size:        528,
		Annotations: Annotations,
	}
	SigManfiestDescriptor = ocispec.Descriptor{
		MediaType:   "application/vnd.cncf.oras.artifact.manifest.v1+json",
		Digest:      SampleDigest,
		Size:        300,
		Annotations: Annotations,
	}
	TestImageDescriptor = ocispec.Descriptor{
		MediaType:   "application/vnd.docker.distribution.manifest.v2+json",
		Digest:      digest.Digest("sha256:fe7e9333395060c2f5e63cf36a38fba10176f183b4163a5794e081a480abba5f"),
		Size:        942,
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
	MetadataSigEnvDescriptor = ocispec.Descriptor{
		MediaType:   "application/vnd.docker.distribution.manifest.v2+json",
		Digest:      digest.Digest("sha256:5a07385af4e6b6af81b0ebfd435aedccdfa3507f0609c658209e1aba57159b2b"),
		Size:        942,
		Annotations: map[string]string{"io.wabbit-networks.buildId": "123", "io.wabbit-networks.buildTime": "1672944615"},
	}
)

type Repository struct {
	ResolveResponse            ocispec.Descriptor
	ResolveError               error
	ListSignaturesResponse     []ocispec.Descriptor
	ListSignaturesError        error
	FetchSignatureBlobResponse []byte
	FetchSignatureBlobError    error
}

func NewRepository() Repository {
	return Repository{
		ResolveResponse:            ImageDescriptor,
		ListSignaturesResponse:     []ocispec.Descriptor{SigManfiestDescriptor},
		FetchSignatureBlobResponse: MockCaValidSigEnv,
	}
}

func (t Repository) Resolve(ctx context.Context, reference string) (ocispec.Descriptor, error) {
	return t.ResolveResponse, t.ResolveError
}

func (t Repository) ListSignatures(ctx context.Context, desc ocispec.Descriptor, fn func(signatureManifests []ocispec.Descriptor) error) error {
	err := fn(t.ListSignaturesResponse)
	if err != nil {
		return err
	}
	return t.ListSignaturesError
}

func (t Repository) FetchSignatureBlob(ctx context.Context, desc ocispec.Descriptor) ([]byte, ocispec.Descriptor, error) {
	return t.FetchSignatureBlobResponse, JwsSigEnvDescriptor, t.FetchSignatureBlobError
}

func (t Repository) PushSignature(ctx context.Context, mediaType string, blob []byte, subject ocispec.Descriptor, annotations map[string]string) (blobDesc, manifestDesc ocispec.Descriptor, err error) {
	return ocispec.Descriptor{}, ocispec.Descriptor{}, nil
}

type PluginMock struct {
	Metadata        proto.GetMetadataResponse
	ExecuteResponse interface{}
	ExecuteError    error
}

func (p *PluginMock) GetMetadata(ctx context.Context, req *proto.GetMetadataRequest) (*proto.GetMetadataResponse, error) {
	return &p.Metadata, nil
}

func (p *PluginMock) VerifySignature(ctx context.Context, req *proto.VerifySignatureRequest) (*proto.VerifySignatureResponse, error) {
	if resp, ok := p.ExecuteResponse.(*proto.VerifySignatureResponse); ok {
		return resp, nil
	}
	return nil, p.ExecuteError
}

func (p *PluginMock) DescribeKey(ctx context.Context, req *proto.DescribeKeyRequest) (*proto.DescribeKeyResponse, error) {
	panic("not implemented") // TODO: Implement
}

func (p *PluginMock) GenerateSignature(ctx context.Context, req *proto.GenerateSignatureRequest) (*proto.GenerateSignatureResponse, error) {
	panic("not implemented") // TODO: Implement
}

func (p *PluginMock) GenerateEnvelope(ctx context.Context, req *proto.GenerateEnvelopeRequest) (*proto.GenerateEnvelopeResponse, error) {
	panic("not implemented") // TODO: Implement
}

type PluginManager struct {
	PluginCapabilities          []proto.Capability
	GetPluginError              error
	PluginRunnerLoadError       error
	PluginRunnerExecuteResponse interface{}
	PluginRunnerExecuteError    error
}

func (pm PluginManager) Get(ctx context.Context, name string) (plugin.Plugin, error) {
	return &PluginMock{
		Metadata: proto.GetMetadataResponse{
			Name:                      "plugin-name",
			Description:               "for mocking in unit tests",
			Version:                   "1.0.0",
			URL:                       ".",
			SupportedContractVersions: []string{"1.0"},
			Capabilities:              pm.PluginCapabilities,
		},
		ExecuteResponse: pm.PluginRunnerExecuteResponse,
		ExecuteError:    pm.PluginRunnerExecuteError,
	}, pm.GetPluginError
}

func (pm PluginManager) List(ctx context.Context) ([]string, error) {
	panic("not implemented")
}
