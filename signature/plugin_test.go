package signature

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/signature/cose"
	"github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/plugin"
	gcose "github.com/veraison/go-cose"
)

const unsupported = "unsupported"

var (
	validMetadata = plugin.Metadata{
		Name:        "testPlugin",
		Description: "plugin for test",
		Version:     "1", URL: "test.com",
		SupportedContractVersions: []string{plugin.ContractVersion},
		Capabilities:              []plugin.Capability{plugin.CapabilitySignatureGenerator},
	}
	validSignDescriptor, validSignOpts = generateSigningContent(nil)
	invalidJwsEnvelope, _              = json.Marshal(struct{}{})
	invalidCoseEnvelope, _             = gcose.NewSign1Message().MarshalCBOR()
	envelopeTypeToData                 = map[string][]byte{
		jws.MediaTypeEnvelope:  invalidJwsEnvelope,
		cose.MediaTypeEnvelope: invalidCoseEnvelope,
	}
)

var (
	validMetaDataWithSigningCapabilityFunc = func(ctx context.Context, req plugin.Request) (interface{}, error) {
		return &validMetadata, nil
	}
	validMetaDataWithEnvelopeGeneratorCapabilityFunc = func(ctx context.Context, req plugin.Request) (interface{}, error) {
		metaData := validMetadata
		metaData.Capabilities = []plugin.Capability{plugin.CapabilityEnvelopeGenerator}
		return &metaData, nil
	}
)

type options struct {
	signFunc
	certChainFunc
	keySpecFunc
	runner *mockRunner
}

type optionFunc func(*options)

type signFunc func([]byte) ([]byte, error)

func withSignFunc(f signFunc) optionFunc {
	return func(o *options) {
		o.signFunc = f
	}
}

type certChainFunc func() ([]*x509.Certificate, error)

func withCertChainFunc(f certChainFunc) optionFunc {
	return func(o *options) {
		o.certChainFunc = f
	}
}

type keySpecFunc func() (signature.KeySpec, error)

func withKeySpecFunc(f keySpecFunc) optionFunc {
	return func(o *options) {
		o.keySpecFunc = f
	}
}

func withRunner(r *mockRunner) optionFunc {
	return func(o *options) {
		o.runner = r
	}
}

type runFunc func(context.Context, plugin.Request) (interface{}, error)

func withRunnerMetaData(f runFunc) optionFunc {
	return func(o *options) {
		mockRunnerWithMetaData(f)(o.runner)
	}
}

func withRunnerDescribeKey(f runFunc) optionFunc {
	return func(o *options) {
		mockRunnerWithDescribeKey(f)(o.runner)
	}
}

func withRunnerGenerateSignature(f runFunc) optionFunc {
	return func(o *options) {
		mockRunnerWithGenerateSignature(f)(o.runner)
	}
}

func withRunnerGenerateEnvelope(f runFunc) optionFunc {
	return func(o *options) {
		mockRunnerWithGenerateEnvelope(f)(o.runner)
	}
}

// mockProvider implements provider
// mockProvider will call function in options first
// If function not exist, it will call function inherited from the provider
type mockProvider struct {
	provider
	options
}

// apply applyes opts to the options field
func (p *mockProvider) apply(opts ...optionFunc) *mockProvider {
	for _, opt := range opts {
		opt(&p.options)
	}
	return p
}

func (p *mockProvider) Sign(digest []byte) ([]byte, error) {
	if p.options.signFunc != nil {
		return p.options.signFunc(digest)
	}
	return p.provider.Sign(digest)
}

func (p *mockProvider) CertificateChain() ([]*x509.Certificate, error) {
	if p.options.certChainFunc != nil {
		return p.options.certChainFunc()
	}
	return p.provider.CertificateChain()
}

func (p *mockProvider) KeySpec() (signature.KeySpec, error) {
	if p.options.keySpecFunc != nil {
		return p.options.keySpecFunc()
	}
	return p.provider.KeySpec()
}

func (p *mockProvider) Run(ctx context.Context, req plugin.Request) (interface{}, error) {
	if p.options.runner != nil {
		return p.options.runner.Run(ctx, req)
	}
	return p.provider.Run(ctx, req)
}

// newMockProvider creates a defaultMockProvider with options
// options wiil override options fields
func newMockProvider(opts ...optionFunc) *mockProvider {
	p := newDefaultMockProvider()
	return p.apply(opts...)
}

// newMockProviderFrom creates a mockProvider from a base provider
// and override some options
func newMockProviderFrom(base *mockProvider, opts ...optionFunc) *mockProvider {
	if base == nil {
		return newMockProvider(opts...)
	}
	return base.apply(opts...)
}

// buildDefaultMockProvider create a mockProvider
// It uses builtin provider as provider
// It uses a mockRunner as runner's option
// All other options are left to nil
func newDefaultMockProvider() *mockProvider {
	return &mockProvider{
		provider: newTestBuiltInProvider(nil),
		options: options{
			runner: newMockRunner(),
		},
	}
}

// newTestBuiltInProvider creates a provider interface with a builtin provider
// if keyCertPair not provided, use a rsa-2048 keySpec
func newTestBuiltInProvider(keyCertPair *keyCertPair) provider {
	if keyCertPair == nil {
		keyCertPair = keyCertPairCollections[0]
	}
	p, err := newBuiltinProvider(keyCertPair.key, keyCertPair.certs)
	if err != nil {
		panic(fmt.Sprintf("create builtin provider failed: %v", err))
	}
	return p
}

type runnerOptions func(*mockRunner)

// mockRunner is a ruuner
// it seperate run function into 4 commands
// by default, all four commands are not implemented and will return an error
type mockRunner struct {
	metaData          runFunc
	describeKey       runFunc
	generateSignature runFunc
	generateEnvelope  runFunc
}

func (m *mockRunner) Run(ctx context.Context, req plugin.Request) (interface{}, error) {
	switch req.Command() {
	case plugin.CommandGetMetadata:
		if m.metaData != nil {
			return m.metaData(ctx, req)
		}
		return nil, fmt.Errorf("command %q is not supported", req.Command())
	case plugin.CommandDescribeKey:
		if m.describeKey != nil {
			return m.describeKey(ctx, req)
		}
		return nil, fmt.Errorf("command %q is not supported", req.Command())
	case plugin.CommandGenerateSignature:
		if m.generateSignature != nil {
			return m.generateSignature(ctx, req)
		}
		return nil, fmt.Errorf("command %q is not supported", req.Command())
	case plugin.CommandGenerateEnvelope:
		if m.generateEnvelope != nil {
			return m.generateEnvelope(ctx, req)
		}
		return nil, fmt.Errorf("command %q is not supported", req.Command())
	}
	return nil, plugin.RequestError{
		Code: plugin.ErrorCodeGeneric,
		Err:  fmt.Errorf("command %q is not supported", req.Command()),
	}
}

func (m *mockRunner) apply(opts ...runnerOptions) *mockRunner {
	for _, opt := range opts {
		opt(m)
	}
	return m
}

func newMockRunner(opts ...runnerOptions) *mockRunner {
	runner := &mockRunner{}
	runner = runner.apply(opts...)
	return runner
}

func mockRunnerWithMetaData(f runFunc) runnerOptions {
	return func(mr *mockRunner) {
		mr.metaData = f
	}
}

func mockRunnerWithDescribeKey(f runFunc) runnerOptions {
	return func(mr *mockRunner) {
		mr.describeKey = f
	}
}

func mockRunnerWithGenerateSignature(f runFunc) runnerOptions {
	return func(mr *mockRunner) {
		mr.generateSignature = f
	}
}

func mockRunnerWithGenerateEnvelope(f runFunc) runnerOptions {
	return func(mr *mockRunner) {
		mr.generateEnvelope = f
	}
}

func testSignerError(t *testing.T, signer pluginSigner, wantEr string) {
	t.Helper()
	_, err := signer.Sign(context.Background(), notation.Descriptor{}, notation.SignOptions{})
	if err == nil || !strings.Contains(err.Error(), wantEr) {
		t.Errorf("Signer.Sign() error = %v, wantErr %v", err, wantEr)
	}
}

func TestSigner_Sign_RunMetadataFails(t *testing.T) {
	t.Run("run metadata command failed", func(t *testing.T) {
		p := newMockProvider(
			withRunnerMetaData(func(ctx context.Context, r plugin.Request) (interface{}, error) {
				return nil, errors.New("metadata command fail")
			}),
		)
		signer := pluginSigner{
			sigProvider: p,
		}
		testSignerError(t, signer, "metadata command failed")
	})

	t.Run("no capability", func(t *testing.T) {
		m := validMetadata
		m.Capabilities = []plugin.Capability{""}
		p := newMockProvider(
			withRunnerMetaData(func(ctx context.Context, r plugin.Request) (interface{}, error) {
				return &m, nil
			}),
		)
		signer := pluginSigner{
			sigProvider: p,
		}
		testSignerError(t, signer, "does not have signing capabilities")
	})

	t.Run("metadata response type error", func(t *testing.T) {
		p := newMockProvider(
			withRunnerMetaData(func(ctx context.Context, r plugin.Request) (interface{}, error) {
				return struct{}{}, nil
			}),
		)
		signer := pluginSigner{
			sigProvider: p,
		}
		testSignerError(t, signer, "plugin runner returned incorrect get-plugin-metadata response type")
	})

	t.Run("invalid metadata", func(t *testing.T) {
		p := newMockProvider(
			withRunnerMetaData(func(ctx context.Context, r plugin.Request) (interface{}, error) {
				return &plugin.Metadata{}, nil
			}),
		)
		signer := pluginSigner{
			sigProvider: p,
		}
		testSignerError(t, signer, "invalid plugin metadata")
	})

	t.Run("plugin contract not supported", func(t *testing.T) {
		p := newMockProvider(
			withRunnerMetaData(func(ctx context.Context, r plugin.Request) (interface{}, error) {
				metaData := validMetadata
				metaData.SupportedContractVersions = []string{unsupported}
				return &metaData, nil
			}),
		)
		signer := pluginSigner{
			sigProvider: p,
		}
		testSignerError(t, signer, fmt.Sprintf("contract version %q is not in the list of the plugin supported versions %v", plugin.ContractVersion, []string{unsupported}))
	})
}

func TestSigner_Sign_DescribeKeyFailed(t *testing.T) {
	t.Run("run describe-key command failed", func(t *testing.T) {
		p := newMockProvider(
			withRunnerMetaData(validMetaDataWithSigningCapabilityFunc),
			withRunnerDescribeKey(func(ctx context.Context, r plugin.Request) (interface{}, error) {
				return nil, errors.New("describle-key command failed")
			}),
		)
		signer := pluginSigner{
			sigProvider: p,
		}
		testSignerError(t, signer, "describe-key command failed")
	})

	t.Run("describe-key response type error", func(t *testing.T) {
		p := newMockProvider(
			withRunnerMetaData(validMetaDataWithSigningCapabilityFunc),
			withRunnerDescribeKey(func(ctx context.Context, r plugin.Request) (interface{}, error) {
				return struct{}{}, nil
			}),
		)
		signer := pluginSigner{
			sigProvider: p,
		}
		testSignerError(t, signer, "plugin runner returned incorrect describe-key response type")
	})
}

func TestSigner_Sign_DescribeKeyKeyIDMismatch(t *testing.T) {
	reqKeyID, respKeyID := "1", "2"
	p := newMockProvider(
		withRunnerMetaData(validMetaDataWithSigningCapabilityFunc),
		withRunnerDescribeKey(func(ctx context.Context, r plugin.Request) (interface{}, error) {
			return &plugin.DescribeKeyResponse{
				KeyID: respKeyID,
			}, nil
		}),
	)
	signer := pluginSigner{
		sigProvider: p,
		keyID:       reqKeyID,
	}
	testSignerError(t, signer, fmt.Sprintf("keyID in describeKey response %q does not match request %q", respKeyID, reqKeyID))
}

func TestSigner_Sign_EnvelopeNotSupported(t *testing.T) {
	p := newMockProvider(
		withRunnerMetaData(validMetaDataWithSigningCapabilityFunc),
		withRunnerDescribeKey(func(ctx context.Context, r plugin.Request) (interface{}, error) {
			return &plugin.DescribeKeyResponse{
				KeyID: r.(*plugin.DescribeKeyRequest).KeyID,
			}, nil
		}),
	)
	signer := pluginSigner{
		sigProvider:       p,
		envelopeMediaType: unsupported,
	}
	testSignerError(t, signer, fmt.Sprintf("signature envelope format with media type %q is not supported", signer.envelopeMediaType))
}

func TestSigner_Sign_KeySpecMisMatchCertChain(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType:%v", envelopeType), func(t *testing.T) {
			p := newMockProvider(
				withRunner(nil),
				withKeySpecFunc(func() (signature.KeySpec, error) {
					return signature.KeySpec{}, nil
				}),
			)
			signer := pluginSigner{
				sigProvider:       p,
				envelopeMediaType: envelopeType,
			}
			testSignerError(t, signer, "mismatch between signature algorithm")
		})
	}
}

func TestSigner_Sign_ExpiryInValid(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType:%v", envelopeType), func(t *testing.T) {
			p := newMockProvider(
				withRunner(nil),
			)
			signer := pluginSigner{
				sigProvider:       p,
				envelopeMediaType: envelopeType,
			}
			_, err := signer.Sign(context.Background(), notation.Descriptor{}, notation.SignOptions{Expiry: time.Now().Add(-100)})
			wantEr := "expiry cannot be equal or before the signing time"
			if err == nil || !strings.Contains(err.Error(), wantEr) {
				t.Errorf("Signer.Sign() error = %v, wantErr %v", err, wantEr)
			}
		})
	}
}

func TestSigner_Sign_GenerateSignatureKeyIDMismatch(t *testing.T) {
	reqKeyID, respKeyID := "1", "2"
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType:%v", envelopeType), func(t *testing.T) {
			extRunner := newMockRunner(
				mockRunnerWithMetaData(validMetaDataWithSigningCapabilityFunc),
				mockRunnerWithDescribeKey(func(ctx context.Context, r plugin.Request) (interface{}, error) {
					_, certs, err := generateKeyCertPair()
					if err != nil {
						return nil, fmt.Errorf("create key-cert pair for mockRunner failed: %v", err)
					}
					keySpec, err := signature.ExtractKeySpec(certs[0])
					if err != nil {
						return nil, fmt.Errorf("extract keySpec for mockRunner failed: %v", err)
					}
					var rawCerts [][]byte
					for _, cert := range certs {
						rawCerts = append(rawCerts, cert.Raw)
					}
					return &plugin.DescribeKeyResponse{
						KeyID:            reqKeyID,
						KeySpec:          KeySpecName(keySpec),
						CertificateChain: rawCerts,
					}, nil
				}),
				mockRunnerWithGenerateSignature(func(ctx context.Context, r plugin.Request) (interface{}, error) {
					return &plugin.GenerateSignatureResponse{
						KeyID: respKeyID,
					}, nil
				}),
			)
			p, err := newExternalProvider(extRunner, reqKeyID)
			if err != nil {
				t.Fatalf("create external provider failed: %v", err)
			}
			signer := pluginSigner{
				sigProvider:       p,
				envelopeMediaType: envelopeType,
				keyID:             reqKeyID,
			}
			testSignerError(t, signer, fmt.Sprintf("keyID in generateSignature response %q does not match request %q", respKeyID, reqKeyID))
		})
	}
}

func TestSigner_Sign_NoCertChain(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType:%v", envelopeType), func(t *testing.T) {
			p := newMockProvider(
				withRunner(nil),
				withCertChainFunc(func() ([]*x509.Certificate, error) {
					return nil, nil
				}),
			)
			signer := pluginSigner{
				sigProvider:       p,
				envelopeMediaType: envelopeType,
			}
			testSignerError(t, signer, "certificate-chain not present or is empty")
		})
	}
}

func TestSigner_Sign_InvalidCertChain(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType:%v", envelopeType), func(t *testing.T) {
			p := newMockProvider(
				withRunner(nil),
				withCertChainFunc(func() ([]*x509.Certificate, error) {
					return []*x509.Certificate{{}, {}}, nil
				}),
			)
			signer := pluginSigner{
				sigProvider:       p,
				envelopeMediaType: envelopeType,
			}
			testSignerError(t, signer, "certificate-chain is invalid")
		})
	}
}

func TestSigner_Sign_SignatureVerifyError(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType:%v", envelopeType), func(t *testing.T) {
			p := newMockProvider(
				withRunner(nil),
				withSignFunc(func(b []byte) ([]byte, error) {
					return []byte(unsupported), nil
				}),
			)
			signer := pluginSigner{
				sigProvider:       p,
				envelopeMediaType: envelopeType,
			}
			testSignerError(t, signer, "signature returned by generateSignature cannot be verified")

		})
	}
}

func basicSignTest(t *testing.T, pluginSigner *pluginSigner) {
	data, err := pluginSigner.Sign(context.Background(), validSignDescriptor, validSignOpts)
	if err != nil {
		t.Fatalf("Signer.Sign() error = %v, wantErr nil", err)
	}
	env, err := signature.ParseEnvelope(pluginSigner.envelopeMediaType, data)
	if err != nil {
		t.Fatal(err)
	}
	payload, signerInfo, err := env.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if payload.ContentType != signature.MediaTypePayloadV1 {
		t.Fatalf("Signer.Sign() Payload content type changed, expect: %v, got: %v", payload.ContentType, signature.MediaTypePayloadV1)
	}
	var gotPayload notation.Payload
	if err := json.Unmarshal(payload.Content, &gotPayload); err != nil {
		t.Fatalf("Signer.Sign() Unmarshal payload failed: %v", err)
	}
	expectedPayload := notation.Payload{
		TargetArtifact: validSignDescriptor,
	}
	if !reflect.DeepEqual(expectedPayload, gotPayload) {
		t.Fatalf("Signer.Sign() descriptor subject changed, expect: %v, got: %v", expectedPayload, *payload)
	}
	if signerInfo.SignedAttributes.SigningScheme != signature.SigningSchemeX509 {
		t.Fatalf("Signer.Sign() signing scheme changed, expect: %v, got: %v", signerInfo.SignedAttributes.SigningScheme, signature.SigningSchemeX509)
	}
	keySpec, err := pluginSigner.sigProvider.KeySpec()
	if err != nil {
		t.Fatalf("Signer.Sign() get signer keySpec failed: %v", err)
	}
	if keySpec.SignatureAlgorithm() != signerInfo.SignatureAlgorithm {
		t.Fatalf("Signer.Sign() signing algorithm changed")
	}
	if validSignOpts.Expiry.Unix() != signerInfo.SignedAttributes.Expiry.Unix() {
		t.Fatalf("Signer.Sign() expiry changed")
	}
	certChain, err := pluginSigner.sigProvider.CertificateChain()
	if err != nil {
		t.Fatalf("Signer.Sign() get signer cert failed: %v", err)
	}
	if !reflect.DeepEqual(certChain, signerInfo.CertificateChain) {
		t.Fatalf(" Signer.Sign() cert chain changed")
	}
	basicVerification(t, data, pluginSigner.envelopeMediaType, certChain[len(certChain)-1])
}

func TestSigner_Sign_Valid(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		for _, keyCert := range keyCertPairCollections {
			t.Run(fmt.Sprintf("envelopeType:%v, keySpec: %v", envelopeType, keyCert.keySpecName), func(t *testing.T) {
				pluginSigner := pluginSigner{
					sigProvider:       newTestBuiltInProvider(keyCert),
					envelopeMediaType: envelopeType,
				}
				basicSignTest(t, &pluginSigner)
			})
		}
	}
}

func TestPluginSigner_SignEnvelope_RunFailed(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType:%v", envelopeType), func(t *testing.T) {
			p := newMockProvider(
				withRunnerMetaData(validMetaDataWithEnvelopeGeneratorCapabilityFunc),
				withRunnerDescribeKey(func(ctx context.Context, r plugin.Request) (interface{}, error) {
					return &plugin.DescribeKeyResponse{
						KeyID: r.(*plugin.DescribeKeyRequest).KeyID,
					}, nil
				}),
			)
			signer := pluginSigner{
				sigProvider:       p,
				envelopeMediaType: envelopeType,
			}
			testSignerError(t, signer, fmt.Sprintf("generate-envelope command failed: command %q is not supported", plugin.CommandGenerateEnvelope))
		})
	}
}

func TestPluginSigner_SignEnvelope_InvalidEnvelopeType(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType:%v", envelopeType), func(t *testing.T) {
			p := newMockProvider(
				withRunnerMetaData(validMetaDataWithEnvelopeGeneratorCapabilityFunc),
				withRunnerDescribeKey(func(ctx context.Context, r plugin.Request) (interface{}, error) {
					return &plugin.DescribeKeyResponse{
						KeyID: r.(*plugin.DescribeKeyRequest).KeyID,
					}, nil
				}),
				withRunnerGenerateEnvelope(func(ctx context.Context, r plugin.Request) (interface{}, error) {
					return &plugin.GenerateEnvelopeResponse{
						SignatureEnvelopeType: unsupported,
					}, nil
				}),
			)
			signer := pluginSigner{
				sigProvider:       p,
				envelopeMediaType: envelopeType,
			}
			testSignerError(t, signer, fmt.Sprintf("signatureEnvelopeType in generateEnvelope response %q does not match request %q", unsupported, envelopeType))
		})
	}
}

// newMockEnvelopeProvider creates a mock envelope provider.
// The provider's runner implements metadata, describe-key and generate-envelope commands by default
// Opts controll how the envelope is created.
// If no opts are provided, it will use a builtin provider to generate a valid signature envelope
// otherwise, it will use a mock provider with options to sign
// opts can be used to inject error for run command
// It will always sign validDesc with validOpts
func newMockEnvelopeProvider(keyCertPair *keyCertPair, opts ...optionFunc) *mockProvider {
	var internalProvider provider
	if len(opts) == 0 {
		internalProvider = newTestBuiltInProvider(keyCertPair)
	} else {
		internalProvider = newMockProvider(append(opts, withRunner(nil))...)
	}
	return newMockProvider(
		withRunnerMetaData(validMetaDataWithEnvelopeGeneratorCapabilityFunc),
		withRunnerDescribeKey(func(ctx context.Context, r plugin.Request) (interface{}, error) {
			var rawCerts [][]byte
			for _, cert := range keyCertPair.certs {
				rawCerts = append(rawCerts, cert.Raw)
			}
			return &plugin.DescribeKeyResponse{
				KeyID:            r.(*plugin.DescribeKeyRequest).KeyID,
				KeySpec:          keyCertPair.keySpecName,
				CertificateChain: rawCerts,
			}, nil
		}),
		withRunnerGenerateEnvelope(func(ctx context.Context, r plugin.Request) (interface{}, error) {
			sigGenerator := pluginSigner{
				sigProvider:       internalProvider,
				envelopeMediaType: r.(*plugin.GenerateEnvelopeRequest).SignatureEnvelopeType,
			}
			// var payload notation.Payload
			// if err := json.Unmarshal(r.(*plugin.GenerateEnvelopeRequest).Payload, &payload); err != nil {
			// 	return nil, err
			// }
			data, err := sigGenerator.Sign(
				context.Background(),
				validSignDescriptor,
				validSignOpts)
			if err != nil {
				return nil, err
			}
			return &plugin.GenerateEnvelopeResponse{
				SignatureEnvelope:     data,
				SignatureEnvelopeType: r.(*plugin.GenerateEnvelopeRequest).SignatureEnvelopeType,
			}, nil
		}),
		withCertChainFunc(internalProvider.CertificateChain),
		withKeySpecFunc(internalProvider.KeySpec),
		withSignFunc(internalProvider.Sign),
	)
}

func TestPluginSigner_SignEnvelope_EmptyCert(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType:%v", envelopeType), func(t *testing.T) {
			signer := pluginSigner{
				sigProvider: newMockEnvelopeProvider(
					nil,
					withCertChainFunc(func() ([]*x509.Certificate, error) {
						return nil, nil
					})),
				envelopeMediaType: envelopeType,
			}
			testSignerError(t, signer, "generate-envelope command failed: certificate-chain not present or is empty")
		})
	}
}

func TestPluginSigner_SignEnvelope_MalformedCertChain(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType:%v", envelopeType), func(t *testing.T) {
			signer := pluginSigner{
				sigProvider: newMockEnvelopeProvider(
					nil,
					withCertChainFunc(func() ([]*x509.Certificate, error) {
						return []*x509.Certificate{{}, {}}, nil
					}),
				),
				envelopeMediaType: envelopeType,
			}
			testSignerError(t, signer, "generate-envelope command failed: certificate-chain is invalid")
		})
	}
}

func TestPluginSigner_SignEnvelope_MalFormedEnvelope(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType:%v", envelopeType), func(t *testing.T) {
			p := newMockProvider(
				withRunnerMetaData(validMetaDataWithEnvelopeGeneratorCapabilityFunc),
				withRunnerDescribeKey(func(ctx context.Context, r plugin.Request) (interface{}, error) {
					return &plugin.DescribeKeyResponse{
						KeyID: r.(*plugin.DescribeKeyRequest).KeyID,
					}, nil
				}),
				withRunnerGenerateEnvelope(func(ctx context.Context, r plugin.Request) (interface{}, error) {
					return &plugin.GenerateEnvelopeResponse{
						SignatureEnvelope:     []byte(unsupported),
						SignatureEnvelopeType: r.(*plugin.GenerateEnvelopeRequest).SignatureEnvelopeType,
					}, nil
				}),
			)
			signer := pluginSigner{
				sigProvider:       p,
				envelopeMediaType: envelopeType,
			}
			var expectedErr *signature.MalformedSignatureError
			if _, err := signer.Sign(context.Background(), notation.Descriptor{}, notation.SignOptions{}); err == nil || !errors.As(err, &expectedErr) {
				t.Fatalf("Signer.Sign() error = %v, want MalformedSignatureError", err)
			}
		})
	}
}

func TestPluginSigner_SignEnvelope_DescriptorChanged(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType:%v", envelopeType), func(t *testing.T) {
			signer := pluginSigner{
				sigProvider:       newMockEnvelopeProvider(nil),
				envelopeMediaType: envelopeType,
			}
			_, err := signer.Sign(context.Background(), notation.Descriptor{}, notation.SignOptions{})
			if err == nil || err.Error() != "descriptor subject has changed" {
				t.Fatalf("Signer.Sign() error = %v, wnatErr descriptor subject has changed", err)
			}
		})
	}
}

func TestPluginSigner_SignEnvelope_SignatureVerifyError(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType:%v", envelopeType), func(t *testing.T) {
			p := newMockProvider(
				withRunnerMetaData(validMetaDataWithEnvelopeGeneratorCapabilityFunc),
				withRunnerDescribeKey(func(ctx context.Context, r plugin.Request) (interface{}, error) {
					return &plugin.DescribeKeyResponse{
						KeyID: r.(*plugin.DescribeKeyRequest).KeyID,
					}, nil
				}),
				withRunnerGenerateEnvelope(func(ctx context.Context, r plugin.Request) (interface{}, error) {
					return &plugin.GenerateEnvelopeResponse{
						SignatureEnvelope:     envelopeTypeToData[envelopeType],
						SignatureEnvelopeType: r.(*plugin.GenerateEnvelopeRequest).SignatureEnvelopeType,
					}, nil
				}),
			)
			signer := pluginSigner{
				sigProvider:       p,
				envelopeMediaType: envelopeType,
			}
			_, err := signer.Sign(context.Background(), notation.Descriptor{}, notation.SignOptions{})
			if err == nil {
				t.Fatalf("Signer.Sign() error = %v", err)
			}
		})
	}
}

func TestPluginSigner_SignEnvelope_Valid(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		for _, keyCert := range keyCertPairCollections {
			t.Run(fmt.Sprintf("envelopeType:%v, keySpec: %v", envelopeType, keyCert.keySpecName), func(t *testing.T) {
				signer := pluginSigner{
					sigProvider:       newMockEnvelopeProvider(keyCert),
					envelopeMediaType: envelopeType,
				}
				basicSignTest(t, &signer)
			})
		}
	}
}
