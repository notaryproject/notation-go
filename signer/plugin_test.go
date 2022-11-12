package signer

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
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/internal/envelope"
	"github.com/notaryproject/notation-go/plugin"
	"github.com/notaryproject/notation-go/plugin/proto"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

var (
	validMetadata = proto.GetMetadataResponse{
		Name:        "testPlugin",
		Description: "plugin for test",
		Version:     "1.0", URL: "test.com",
		SupportedContractVersions: []string{proto.ContractVersion},
		Capabilities:              []proto.Capability{proto.CapabilitySignatureGenerator},
	}
	validSignDescriptor, validSignOpts = generateSigningContent(nil)
	invalidSignatureEnvelope           = []byte("invalid")
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

type mockRemoteSigner struct {
	keyID            string
	key              crypto.PrivateKey
	certs            []*x509.Certificate
	config           map[string]string
	keySpec          signature.KeySpec
	invalidSig       bool
	invalidCertChain bool
}

func newMockRemoteSigner(key crypto.PrivateKey, certs []*x509.Certificate, keyID string, keySpec signature.KeySpec) *mockRemoteSigner {
	return &mockRemoteSigner{
		key:     key,
		certs:   certs,
		keyID:   keyID,
		keySpec: keySpec,
	}
}

func (p *mockRemoteSigner) SetConfig(config map[string]string) {
	p.config = config
}

func (p *mockRemoteSigner) Sign(payload []byte) ([]byte, []*x509.Certificate, error) {
	keySpec, err := p.KeySpec()
	if err != nil {
		return nil, nil, err
	}
	sig, err := localSign(payload, keySpec.SignatureAlgorithm().Hash(), p.key)
	if p.invalidSig {
		return invalidSignatureEnvelope, p.certs, err
	}
	if p.invalidCertChain {
		return sig, []*x509.Certificate{{}, {}}, nil
	}
	return sig, p.certs, err
}

func (p *mockRemoteSigner) KeySpec() (signature.KeySpec, error) {
	return signature.ExtractKeySpec(p.certs[0])
}

type mockPlugin struct {
	failEnvelope bool
	wantEnvelope bool
	key          crypto.PrivateKey
	certs        []*x509.Certificate
	keySpec      signature.KeySpec
}

func newMockPlugin() *mockPlugin {
	return &mockPlugin{}
}

func (p *mockPlugin) GetMetadata(ctx context.Context, req *proto.GetMetadataRequest) (*proto.GetMetadataResponse, error) {
	if p.wantEnvelope {
		return &proto.GetMetadataResponse{
			SupportedContractVersions: []string{proto.ContractVersion},
			Capabilities:              []proto.Capability{proto.CapabilityEnvelopeGenerator},
		}, nil
	}
	return &proto.GetMetadataResponse{
		SupportedContractVersions: []string{proto.ContractVersion},
		Capabilities:              []proto.Capability{proto.CapabilitySignatureGenerator},
	}, nil
}

// DescribeKey returns the KeySpec of a key.
func (p *mockPlugin) DescribeKey(ctx context.Context, req *proto.DescribeKeyRequest) (*proto.DescribeKeyResponse, error) {
	return &proto.DescribeKeyResponse{
		KeySpec: string(proto.KeySpecRSA2048),
	}, nil
}

// GenerateSignature generates the raw signature based on the request.
func (p *mockPlugin) GenerateSignature(ctx context.Context, req *proto.GenerateSignatureRequest) (*proto.GenerateSignatureResponse, error) {
	return &proto.GenerateSignatureResponse{}, nil
}

// GenerateEnvelope generates the Envelope with signature based on the request.
func (p *mockPlugin) GenerateEnvelope(ctx context.Context, req *proto.GenerateEnvelopeRequest) (*proto.GenerateEnvelopeResponse, error) {
	if p.failEnvelope {
		return nil, errors.New("failed GenerateEnvelope")
	}
	if p.wantEnvelope {
		internalPluginSigner := pluginSigner{
			plugin: newMockPlugin(),
			signer: newMockRemoteSigner(p.key, p.certs, "", p.keySpec),
		}
		var payload envelope.Payload
		if err := json.Unmarshal(req.Payload, &payload); err != nil {
			return nil, err
		}
		validSignOpts.SignatureMediaType = req.SignatureEnvelopeType
		data, _, err := internalPluginSigner.Sign(ctx, payload.TargetArtifact, validSignOpts)
		if err != nil {
			return nil, err
		}
		return &proto.GenerateEnvelopeResponse{
			SignatureEnvelope:     data,
			SignatureEnvelopeType: req.SignatureEnvelopeType,
		}, nil
	}
	return &proto.GenerateEnvelopeResponse{}, nil
}

func testSignerError(t *testing.T, signer pluginSigner, wantEr string, opts notation.SignOptions) {
	t.Helper()
	_, _, err := signer.Sign(context.Background(), ocispec.Descriptor{}, opts)
	if err == nil || !strings.Contains(err.Error(), wantEr) {
		t.Errorf("Signer.Sign() error = %v, wantErr %v", err, wantEr)
	}
}

func TestNewFromPluginFailed(t *testing.T) {
	wantErr := "nil signing keyID"
	_, err := NewFromPlugin(&plugin.CLIPlugin{}, "", make(map[string]string))
	if err == nil || err.Error() != wantErr {
		t.Fatalf("TestNewFromPluginFailed expects error %q, got %q", wantErr, err.Error())
	}
}

func TestSigner_Sign_EnvelopeNotSupported(t *testing.T) {
	signer := pluginSigner{
		plugin: newMockPlugin(),
	}
	opts := notation.SignOptions{SignatureMediaType: "unsupported"}
	testSignerError(t, signer, fmt.Sprintf("signature envelope format with media type %q is not supported", opts.SignatureMediaType), opts)
}

func TestSigner_Sign_DescribeKeyIDMismatch(t *testing.T) {
	respKeyId := ""
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType=%v", envelopeType), func(t *testing.T) {
			signer := pluginSigner{
				plugin: newMockPlugin(),
				keyID:  "1",
			}
			testSignerError(t, signer, fmt.Sprintf("keyID in describeKey response %q does not match request %q", respKeyId, signer.keyID), notation.SignOptions{SignatureMediaType: envelopeType})
		})
	}
}

func TestSigner_Sign_ExpiryInValid(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType=%v", envelopeType), func(t *testing.T) {
			ks, _ := signature.ExtractKeySpec(keyCertPairCollections[0].certs[0])
			remoteSigner := newMockRemoteSigner(keyCertPairCollections[0].key, keyCertPairCollections[0].certs, "", ks)
			signer := pluginSigner{
				plugin: newMockPlugin(),
				signer: remoteSigner,
			}
			_, _, err := signer.Sign(context.Background(), ocispec.Descriptor{}, notation.SignOptions{Expiry: time.Now().Add(-100), SignatureMediaType: envelopeType})
			wantEr := "expiry cannot be equal or before the signing time"
			if err == nil || !strings.Contains(err.Error(), wantEr) {
				t.Errorf("Signer.Sign() error = %v, wantErr %v", err, wantEr)
			}
		})
	}
}

func TestSigner_Sign_InvalidCertChain(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType=%v", envelopeType), func(t *testing.T) {
			p := newMockRemoteSigner(
				defaultKeyCert.key,
				defaultKeyCert.certs,
				"",
				defaultKeySpec,
			)
			p.invalidCertChain = true
			signer := pluginSigner{
				plugin: newMockPlugin(),
				signer: p,
			}
			testSignerError(t, signer, "x509: malformed certificate", notation.SignOptions{SignatureMediaType: envelopeType})
		})
	}
}

func TestPluginSigner_Sign_SignatureVerifyError(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType=%v", envelopeType), func(t *testing.T) {
			p := newMockRemoteSigner(
				defaultKeyCert.key,
				defaultKeyCert.certs,
				"",
				defaultKeySpec,
			)
			p.invalidSig = true
			signer := pluginSigner{
				plugin: newMockPlugin(),
				signer: p,
			}
			testSignerError(t, signer, "signature returned by generateSignature cannot be verified", notation.SignOptions{SignatureMediaType: envelopeType})
		})
	}
}

func TestPluginSigner_Sign_Valid(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		for _, keyCert := range keyCertPairCollections {
			t.Run(fmt.Sprintf("external plugin,envelopeType=%v_keySpec=%v", envelopeType, keyCert.keySpecName), func(t *testing.T) {
				keySpec, _ := proto.DecodeKeySpec(proto.KeySpec(keyCert.keySpecName))
				pluginSigner := pluginSigner{
					plugin: newMockPlugin(),
					signer: newMockRemoteSigner(keyCert.key, keyCert.certs, "", keySpec),
				}
				basicSignTest(t, &pluginSigner, envelopeType)
			})
		}
	}
}

func basicSignTest(t *testing.T, pluginSigner *pluginSigner, envelopeType string) {
	validSignOpts.SignatureMediaType = envelopeType
	data, signerInfo, err := pluginSigner.Sign(context.Background(), validSignDescriptor, validSignOpts)
	if err != nil {
		t.Fatalf("Signer.Sign() error = %v, wantErr nil", err)
	}
	env, err := signature.ParseEnvelope(envelopeType, data)
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

	payload := envContent.Payload
	if payload.ContentType != mediaTypePayloadV1 {
		t.Fatalf("Signer.Sign() Payload content type changed, expect: %v, got: %v", payload.ContentType, mediaTypePayloadV1)
	}
	var gotPayload envelope.Payload
	if err := json.Unmarshal(payload.Content, &gotPayload); err != nil {
		t.Fatalf("Signer.Sign() Unmarshal payload failed: %v", err)
	}
	expectedPayload := envelope.Payload{
		TargetArtifact: validSignDescriptor,
	}
	if !reflect.DeepEqual(expectedPayload, gotPayload) {
		t.Fatalf("Signer.Sign() descriptor subject changed, expect: %v, got: %v", expectedPayload, payload)
	}
	if signerInfo.SignedAttributes.SigningScheme != signature.SigningSchemeX509 {
		t.Fatalf("Signer.Sign() signing scheme changed, expect: %v, got: %v", signerInfo.SignedAttributes.SigningScheme, signature.SigningSchemeX509)
	}
	keySpec, err := pluginSigner.signer.KeySpec()
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
	if mockRemoteSigner, ok := pluginSigner.signer.(*mockRemoteSigner); ok {
		certChain = mockRemoteSigner.certs
	}
	if !reflect.DeepEqual(certChain, signerInfo.CertificateChain) {
		t.Fatalf(" Signer.Sign() cert chain changed")
	}
	basicVerification(t, data, envelopeType, certChain[len(certChain)-1])
}

func TestPluginSigner_SignEnvelope_RunFailed(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType=%v", envelopeType), func(t *testing.T) {
			p := &mockPlugin{
				wantEnvelope: true,
				failEnvelope: true,
			}
			signer := pluginSigner{
				plugin: p,
			}
			testSignerError(t, signer, "generate-envelope command failed: failed GenerateEnvelope", notation.SignOptions{SignatureMediaType: envelopeType})
		})
	}
}

func TestPluginSigner_SignEnvelope_Valid(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		for _, keyCert := range keyCertPairCollections {
			t.Run(fmt.Sprintf("envelopeType=%v, keySpec: %v", envelopeType, keyCert.keySpecName), func(t *testing.T) {
				keySpec, _ := proto.DecodeKeySpec(proto.KeySpec(keyCert.keySpecName))
				p := newMockPlugin()
				p.wantEnvelope = true
				p.key = keyCert.key
				p.certs = keyCert.certs
				p.keySpec = keySpec
				pluginSigner := pluginSigner{
					plugin: p,
					signer: newMockRemoteSigner(keyCert.key, keyCert.certs, "", keySpec),
				}
				basicSignTest(t, &pluginSigner, envelopeType)
			})
		}
	}
}
