package signature

import (
	"context"
	"crypto"
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
		Version:     "1.0", URL: "test.com",
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
	invalidSignatureEnvelope = []byte("invalid")
)

var (
	validMetaDataWithEnvelopeGeneratorCapabilityFunc = func(ctx context.Context, req plugin.Request) (interface{}, error) {
		metaData := validMetadata
		metaData.Capabilities = []plugin.Capability{plugin.CapabilityEnvelopeGenerator}
		return &metaData, nil
	}
)

var (
	defaultKeyCert *keyCertPair
	defaultKeySpec signature.KeySpec
)

func init() {
	keyCertPairCollections = setUpKeyCertPairCollections()
	defaultKeyCert = keyCertPairCollections[0]
	defaultKeySpec, _ = signature.ExtractKeySpec(defaultKeyCert.certs[0])
}

type runnerOptions struct {
	metaData          runFunc
	describeKey       runFunc
	generateSignature runFunc
	generateEnvelope  runFunc
}

type options struct {
	signFunc
	keySpecFunc
	runnerOptions
}

type optionFunc func(*options)

type signFunc func([]byte) ([]byte, []*x509.Certificate, error)

func withSignFunc(f signFunc) optionFunc {
	return func(o *options) {
		o.signFunc = f
	}
}

type keySpecFunc func() (signature.KeySpec, error)

func withKeySpecFunc(f keySpecFunc) optionFunc {
	return func(o *options) {
		o.keySpecFunc = f
	}
}

type runFunc func(context.Context, plugin.Request) (interface{}, error)

func withMetaData(f runFunc) optionFunc {
	return func(o *options) {
		o.metaData = f
	}
}

func withDescribeKey(f runFunc) optionFunc {
	return func(o *options) {
		o.describeKey = f
	}
}

func withGenerateSignature(f runFunc) optionFunc {
	return func(o *options) {
		o.generateSignature = f
	}
}

func withGenerateEnvelope(f runFunc) optionFunc {
	return func(o *options) {
		o.generateEnvelope = f
	}
}

type mockProvider struct {
	options
	keyID  string
	key    crypto.PrivateKey
	certs  []*x509.Certificate
	config map[string]string
}

func (p *mockProvider) apply(opts ...optionFunc) *mockProvider {
	for _, opt := range opts {
		opt(&p.options)
	}
	return p
}

func newMockProvider(key crypto.PrivateKey, certs []*x509.Certificate, keyID string, opts ...optionFunc) *mockProvider {
	p := &mockProvider{
		key:   key,
		certs: certs,
		keyID: keyID,
	}
	return p.apply(opts...)
}

func (p *mockProvider) SetConfig(config map[string]string) {
	p.config = config
}

func (p *mockProvider) Sign(payload []byte) ([]byte, []*x509.Certificate, error) {
	if p.options.signFunc != nil {
		return p.options.signFunc(payload)
	}
	keySpec, err := p.KeySpec()
	if err != nil {
		return nil, nil, err
	}
	sig, err := localSign(payload, keySpec.SignatureAlgorithm().Hash(), p.key)
	return sig, p.certs, err
}

func (p *mockProvider) KeySpec() (signature.KeySpec, error) {
	if p.options.keySpecFunc != nil {
		return p.options.keySpecFunc()
	}
	return signature.ExtractKeySpec(p.certs[0])
}

func (p *mockProvider) Run(ctx context.Context, req plugin.Request) (interface{}, error) {
	switch req.Command() {
	case plugin.CommandGetMetadata:
		if p.metaData != nil {
			return p.metaData(ctx, req)
		}
		return &validMetadata, nil
	case plugin.CommandDescribeKey:
		if p.describeKey != nil {
			return p.describeKey(ctx, req)
		}
		keySpec, err := p.KeySpec()
		if err != nil {
			return nil, err
		}
		return &plugin.DescribeKeyResponse{
			KeyID:   p.keyID,
			KeySpec: plugin.KeySpecString(keySpec),
		}, nil
	case plugin.CommandGenerateSignature:
		if p.generateSignature != nil {
			return p.generateSignature(ctx, req)
		}
		r := req.(*plugin.GenerateSignatureRequest)
		sig, _, err := p.Sign(r.Payload)
		if err != nil {
			return nil, err
		}
		keySpec, err := p.KeySpec()
		if err != nil {
			return nil, err
		}
		var certs [][]byte
		for _, cert := range p.certs {
			certs = append(certs, cert.Raw)
		}
		return &plugin.GenerateSignatureResponse{
			KeyID:            p.keyID,
			Signature:        sig,
			SigningAlgorithm: plugin.SigningAlgorithmString(keySpec.SignatureAlgorithm()),
			CertificateChain: certs,
		}, nil
	case plugin.CommandGenerateEnvelope:
		if p.generateEnvelope != nil {
			return p.generateEnvelope(ctx, req)
		}
		return nil, fmt.Errorf("command %q is not supported", req.Command())
	}
	return nil, plugin.RequestError{
		Code: plugin.ErrorCodeGeneric,
		Err:  fmt.Errorf("command %q is not supported", req.Command()),
	}
}

func newDefaultMockProvider(opts ...optionFunc) *mockProvider {
	return newMockProvider(defaultKeyCert.key, defaultKeyCert.certs, "", opts...)
}

func newTestBuiltInProvider(keyCertPair *keyCertPair) provider {
	if keyCertPair == nil {
		keyCertPair = defaultKeyCert
	}
	p, err := newBuiltinProvider(keyCertPair.key, keyCertPair.certs)
	if err != nil {
		panic(fmt.Sprintf("create builtin provider failed: %v", err))
	}
	return p
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
		p := newDefaultMockProvider(
			withMetaData(func(ctx context.Context, r plugin.Request) (interface{}, error) {
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
		p := newDefaultMockProvider(
			withMetaData(func(ctx context.Context, r plugin.Request) (interface{}, error) {
				return &m, nil
			}),
		)
		signer := pluginSigner{
			sigProvider: p,
		}
		testSignerError(t, signer, "does not have signing capabilities")
	})

	t.Run("metadata response type error", func(t *testing.T) {
		p := newDefaultMockProvider(
			withMetaData(func(ctx context.Context, r plugin.Request) (interface{}, error) {
				return struct{}{}, nil
			}),
		)
		signer := pluginSigner{
			sigProvider: p,
		}
		testSignerError(t, signer, "plugin runner returned incorrect get-plugin-metadata response type")
	})

	t.Run("invalid metadata", func(t *testing.T) {
		p := newDefaultMockProvider(
			withMetaData(func(ctx context.Context, r plugin.Request) (interface{}, error) {
				return &plugin.Metadata{}, nil
			}),
		)
		signer := pluginSigner{
			sigProvider: p,
		}
		testSignerError(t, signer, "invalid plugin metadata")
	})

	t.Run("plugin contract not supported", func(t *testing.T) {
		p := newDefaultMockProvider(
			withMetaData(func(ctx context.Context, r plugin.Request) (interface{}, error) {
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
		p := newDefaultMockProvider(
			withDescribeKey(func(ctx context.Context, r plugin.Request) (interface{}, error) {
				return nil, errors.New("describle-key command failed")
			}),
		)
		signer := pluginSigner{
			sigProvider: p,
		}
		testSignerError(t, signer, "describe-key command failed")
	})

	t.Run("describe-key response type error", func(t *testing.T) {
		p := newDefaultMockProvider(
			withDescribeKey(func(ctx context.Context, r plugin.Request) (interface{}, error) {
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
	p := newDefaultMockProvider()
	p.keyID = respKeyID
	signer := pluginSigner{
		sigProvider: p,
		keyID:       reqKeyID,
	}
	testSignerError(t, signer, fmt.Sprintf("keyID in describeKey response %q does not match request %q", respKeyID, reqKeyID))
}

func TestSigner_Sign_EnvelopeNotSupported(t *testing.T) {
	signer := pluginSigner{
		sigProvider:       newDefaultMockProvider(),
		envelopeMediaType: unsupported,
	}
	testSignerError(t, signer, fmt.Sprintf("signature envelope format with media type %q is not supported", signer.envelopeMediaType))
}

func TestSigner_Sign_KeySpecMisMatchCertChain(t *testing.T) {
	// default keySpec would be RSA_2048
	misMatchKeySpec, _ := signature.ExtractKeySpec(keyCertPairCollections[1].certs[0])
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType=%v", envelopeType), func(t *testing.T) {
			p := newDefaultMockProvider(
				withKeySpecFunc(func() (signature.KeySpec, error) {
					return misMatchKeySpec, nil
				}),
			)
			signer := pluginSigner{
				sigProvider:       p,
				envelopeMediaType: envelopeType,
			}
			testSignerError(t, signer, "mismatch between signature algorithm derived from signing certificate")
		})
	}
}

func TestSigner_Sign_ExpiryInValid(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType=%v", envelopeType), func(t *testing.T) {
			signer := pluginSigner{
				sigProvider:       newDefaultMockProvider(),
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
		t.Run(fmt.Sprintf("envelopeType=%v", envelopeType), func(t *testing.T) {
			extRunner := newDefaultMockProvider(
				withGenerateSignature(func(ctx context.Context, r plugin.Request) (interface{}, error) {
					return &plugin.GenerateSignatureResponse{
						KeyID: respKeyID,
					}, nil
				}),
			)
			extRunner.keyID = reqKeyID
			signer := pluginSigner{
				sigProvider:       newExternalProvider(extRunner, reqKeyID),
				envelopeMediaType: envelopeType,
				keyID:             reqKeyID,
			}
			testSignerError(t, signer, fmt.Sprintf("keyID in generateSignature response %q does not match request %q", respKeyID, reqKeyID))
		})
	}
}

func TestSigner_Sign_NoCertChain(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType=%v", envelopeType), func(t *testing.T) {
			p := newMockProvider(
				defaultKeyCert.key,
				defaultKeyCert.certs,
				"",
				withSignFunc(func(b []byte) ([]byte, []*x509.Certificate, error) {
					sig, err := localSign(b, defaultKeySpec.SignatureAlgorithm().Hash(), defaultKeyCert.key)
					if err != nil {
						return nil, nil, err
					}
					return sig, nil, nil
				}),
			)
			signer := pluginSigner{
				sigProvider:       p,
				envelopeMediaType: envelopeType,
			}
			if _, err := signer.Sign(context.Background(), notation.Descriptor{}, notation.SignOptions{}); err == nil {
				t.Errorf("Signer.Sign() expect error")
			}
		})
	}
}

func TestSigner_Sign_InvalidCertChain(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType=%v", envelopeType), func(t *testing.T) {
			p := newMockProvider(
				defaultKeyCert.key,
				defaultKeyCert.certs,
				"",
				withSignFunc(func(b []byte) ([]byte, []*x509.Certificate, error) {
					sig, err := localSign(b, defaultKeySpec.SignatureAlgorithm().Hash(), defaultKeyCert.key)
					if err != nil {
						return nil, nil, err
					}
					// mismatch certs and signature
					return sig, []*x509.Certificate{{}, {}}, nil
				}),
			)
			signer := pluginSigner{
				sigProvider:       p,
				envelopeMediaType: envelopeType,
			}
			testSignerError(t, signer, "x509: malformed certificate")
		})
	}
}

func TestSigner_Sign_SignatureVerifyError(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType=%v", envelopeType), func(t *testing.T) {
			p := newMockProvider(
				defaultKeyCert.key,
				defaultKeyCert.certs,
				"",
				withSignFunc(func(b []byte) ([]byte, []*x509.Certificate, error) {
					return invalidSignatureEnvelope, defaultKeyCert.certs, nil
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
	envContent, err := env.Verify()
	if err != nil {
		t.Fatal(err)
	}

	if err := ValidatePayloadContentType(&envContent.Payload); err != nil {
		t.Fatalf("verification failed. error = %v", err)
	}

	payload, signerInfo := envContent.Payload, envContent.SignerInfo
	if payload.ContentType != notation.MediaTypePayloadV1 {
		t.Fatalf("Signer.Sign() Payload content type changed, expect: %v, got: %v", payload.ContentType, notation.MediaTypePayloadV1)
	}
	var gotPayload notation.Payload
	if err := json.Unmarshal(payload.Content, &gotPayload); err != nil {
		t.Fatalf("Signer.Sign() Unmarshal payload failed: %v", err)
	}
	expectedPayload := notation.Payload{
		TargetArtifact: validSignDescriptor,
	}
	if !reflect.DeepEqual(expectedPayload, gotPayload) {
		t.Fatalf("Signer.Sign() descriptor subject changed, expect: %v, got: %v", expectedPayload, payload)
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
	var certChain []*x509.Certificate

	switch s := pluginSigner.sigProvider.(type) {
	case *builtinProvider:
		certChain, err = s.CertificateChain()
	case *mockProvider:
		certChain = s.certs
	default:
		t.Log("Unknown provider type")
		return
	}
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
			t.Run(fmt.Sprintf("builtin plugin,envelopeType=%v_keySpec=%v", envelopeType, keyCert.keySpecName), func(t *testing.T) {
				pluginSigner := pluginSigner{
					sigProvider:       newTestBuiltInProvider(keyCert),
					envelopeMediaType: envelopeType,
				}
				basicSignTest(t, &pluginSigner)
			})
			keyID := "Key"
			t.Run(fmt.Sprintf("external plugin,envelopeType=%v_keySpec=%v", envelopeType, keyCert.keySpecName), func(t *testing.T) {
				pluginSigner := pluginSigner{
					sigProvider:       newMockProvider(keyCert.key, keyCert.certs, keyID),
					envelopeMediaType: envelopeType,
					keyID:             keyID,
				}
				basicSignTest(t, &pluginSigner)
			})
		}
	}
}

func TestPluginSigner_SignEnvelope_RunFailed(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType=%v", envelopeType), func(t *testing.T) {
			p := newDefaultMockProvider(
				withMetaData(validMetaDataWithEnvelopeGeneratorCapabilityFunc),
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
		t.Run(fmt.Sprintf("envelopeType=%v", envelopeType), func(t *testing.T) {
			p := newDefaultMockProvider(
				withMetaData(validMetaDataWithEnvelopeGeneratorCapabilityFunc),
				withGenerateEnvelope(func(ctx context.Context, r plugin.Request) (interface{}, error) {
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
func newMockEnvelopeProvider(key crypto.PrivateKey, certs []*x509.Certificate, keyID string, opts ...optionFunc) *mockProvider {
	internalProvider := newMockProvider(key, certs, "")
	p := newMockProvider(
		key,
		certs,
		keyID,
		withMetaData(validMetaDataWithEnvelopeGeneratorCapabilityFunc),
		withGenerateEnvelope(func(ctx context.Context, r plugin.Request) (interface{}, error) {
			sigGenerator := pluginSigner{
				sigProvider:       internalProvider,
				envelopeMediaType: r.(*plugin.GenerateEnvelopeRequest).SignatureEnvelopeType,
			}
			var payload notation.Payload
			if err := json.Unmarshal(r.(*plugin.GenerateEnvelopeRequest).Payload, &payload); err != nil {
				return nil, err
			}
			data, err := sigGenerator.Sign(
				context.Background(),
				payload.TargetArtifact,
				validSignOpts)
			if err != nil {
				return nil, err
			}
			return &plugin.GenerateEnvelopeResponse{
				SignatureEnvelope:     data,
				SignatureEnvelopeType: r.(*plugin.GenerateEnvelopeRequest).SignatureEnvelopeType,
			}, nil
		}),
	)
	return p.apply(opts...)
}

func newDefaultMockEnvelopeProvider(opts ...optionFunc) *mockProvider {
	return newMockEnvelopeProvider(defaultKeyCert.key, defaultKeyCert.certs, "", opts...)
}

func TestPluginSigner_SignEnvelope_EmptyCert(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType=%v", envelopeType), func(t *testing.T) {
			signer := pluginSigner{
				sigProvider: newDefaultMockEnvelopeProvider(
					withGenerateEnvelope(func(ctx context.Context, r plugin.Request) (interface{}, error) {
						sigGenerator := pluginSigner{
							sigProvider: newDefaultMockProvider(
								withSignFunc(func(b []byte) ([]byte, []*x509.Certificate, error) {
									sig, err := localSign(b, defaultKeySpec.SignatureAlgorithm().Hash(), defaultKeyCert.key)
									if err != nil {
										return nil, nil, err
									}
									return sig, nil, nil
								}),
							),
							envelopeMediaType: r.(*plugin.GenerateEnvelopeRequest).SignatureEnvelopeType,
						}
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
				),
				envelopeMediaType: envelopeType,
			}
			if _, err := signer.Sign(context.Background(), validSignDescriptor, validSignOpts); err == nil {
				t.Errorf("Signer.Sign() expect error")
			}
		})
	}
}

func TestPluginSigner_SignEnvelope_MalformedCertChain(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType=%v", envelopeType), func(t *testing.T) {
			signer := pluginSigner{
				sigProvider: newDefaultMockEnvelopeProvider(
					withGenerateEnvelope(func(ctx context.Context, r plugin.Request) (interface{}, error) {
						sigGenerator := pluginSigner{
							sigProvider: newDefaultMockProvider(
								withSignFunc(func(b []byte) ([]byte, []*x509.Certificate, error) {
									sig, err := localSign(b, defaultKeySpec.SignatureAlgorithm().Hash(), defaultKeyCert.key)
									if err != nil {
										return nil, nil, err
									}
									return sig, []*x509.Certificate{{}, {}}, nil
								}),
							),
							envelopeMediaType: r.(*plugin.GenerateEnvelopeRequest).SignatureEnvelopeType,
						}
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
				),
				envelopeMediaType: envelopeType,
			}
			testSignerError(t, signer, "x509: malformed certificate")
		})
	}
}

func TestPluginSigner_SignEnvelope_ResponseTypeError(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType=%v", envelopeType), func(t *testing.T) {
			signer := pluginSigner{
				sigProvider: newMockEnvelopeProvider(
					defaultKeyCert.key,
					defaultKeyCert.certs,
					"",
					withGenerateEnvelope(func(ctx context.Context, r plugin.Request) (interface{}, error) {
						return struct{}{}, nil
					}),
				),
				envelopeMediaType: envelopeType,
			}
			testSignerError(t, signer, "plugin runner returned incorrect generate-envelope response type")
		})
	}
}

func TestPluginSigner_SignEnvelope_MalFormedEnvelope(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType=%v", envelopeType), func(t *testing.T) {
			p := newDefaultMockEnvelopeProvider(
				withGenerateEnvelope(func(ctx context.Context, r plugin.Request) (interface{}, error) {
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
			var expectedErr *signature.InvalidSignatureError
			if _, err := signer.Sign(context.Background(), notation.Descriptor{}, notation.SignOptions{}); err == nil || !errors.As(err, &expectedErr) {
				t.Fatalf("Signer.Sign() error = %v, want MalformedSignatureError", err)
			}
		})
	}
}

func TestPluginSigner_SignEnvelope_DescriptorChanged(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType=%v", envelopeType), func(t *testing.T) {
			signer := pluginSigner{
				sigProvider: newDefaultMockEnvelopeProvider(
					withGenerateEnvelope(func(ctx context.Context, r plugin.Request) (interface{}, error) {
						sigGenerator := pluginSigner{
							sigProvider:       newDefaultMockProvider(),
							envelopeMediaType: r.(*plugin.GenerateEnvelopeRequest).SignatureEnvelopeType,
						}
						data, err := sigGenerator.Sign(
							context.Background(),
							notation.Descriptor{
								MediaType: invalidMediaType,
							},
							notation.SignOptions{})
						if err != nil {
							return nil, err
						}
						return &plugin.GenerateEnvelopeResponse{
							SignatureEnvelope:     data,
							SignatureEnvelopeType: r.(*plugin.GenerateEnvelopeRequest).SignatureEnvelopeType,
						}, nil
					}),
				),
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
		t.Run(fmt.Sprintf("envelopeType=%v", envelopeType), func(t *testing.T) {
			p := newDefaultMockEnvelopeProvider(
				withGenerateEnvelope(func(ctx context.Context, r plugin.Request) (interface{}, error) {
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
			t.Run(fmt.Sprintf("envelopeType=%v, keySpec: %v", envelopeType, keyCert.keySpecName), func(t *testing.T) {
				signer := pluginSigner{
					sigProvider:       newMockEnvelopeProvider(keyCert.key, keyCert.certs, ""),
					envelopeMediaType: envelopeType,
				}
				basicSignTest(t, &signer)
			})
		}
	}
}
