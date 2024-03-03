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
	_ "github.com/notaryproject/notation-core-go/signature/cose"
	_ "github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/internal/envelope"
	"github.com/notaryproject/notation-go/plugin"
	"github.com/notaryproject/notation-go/plugin/proto"
	"github.com/opencontainers/go-digest"
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
	validSignDescriptor, validSignOpts = generateSigningContent()
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

type mockPlugin struct {
	failEnvelope      bool
	wantEnvelope      bool
	invalidSig        bool
	invalidCertChain  bool
	invalidDescriptor bool
	annotations       map[string]string
	key               crypto.PrivateKey
	certs             []*x509.Certificate
	keySpec           signature.KeySpec
}

func getDescriptorFunc(throwError bool) func(hashAlgo digest.Algorithm) (ocispec.Descriptor, error) {
	return func(hashAlgo digest.Algorithm) (ocispec.Descriptor, error) {
		if throwError {
			return ocispec.Descriptor{}, errors.New("")
		}
		return validSignDescriptor, nil
	}

}

func newMockPlugin(key crypto.PrivateKey, certs []*x509.Certificate, keySpec signature.KeySpec) *mockPlugin {
	return &mockPlugin{
		key:     key,
		certs:   certs,
		keySpec: keySpec,
	}
}

func (p *mockPlugin) GetMetadata(ctx context.Context, req *proto.GetMetadataRequest) (*proto.GetMetadataResponse, error) {
	if p.wantEnvelope {
		return &proto.GetMetadataResponse{
			Name:                      "testPlugin",
			Version:                   "1.0",
			SupportedContractVersions: []string{proto.ContractVersion},
			Capabilities:              []proto.Capability{proto.CapabilityEnvelopeGenerator},
		}, nil
	}
	return &proto.GetMetadataResponse{
		Name:                      "testPlugin",
		Version:                   "1.0",
		SupportedContractVersions: []string{proto.ContractVersion},
		Capabilities:              []proto.Capability{proto.CapabilitySignatureGenerator},
	}, nil
}

// DescribeKey returns the KeySpec of a key.
func (p *mockPlugin) DescribeKey(ctx context.Context, req *proto.DescribeKeyRequest) (*proto.DescribeKeyResponse, error) {
	ks, _ := proto.EncodeKeySpec(p.keySpec)
	return &proto.DescribeKeyResponse{
		KeySpec: ks,
	}, nil
}

// GenerateSignature generates the raw signature based on the request.
func (p *mockPlugin) GenerateSignature(ctx context.Context, req *proto.GenerateSignatureRequest) (*proto.GenerateSignatureResponse, error) {
	sig, err := localSign(req.Payload, p.keySpec.SignatureAlgorithm().Hash(), p.key)
	var certChain [][]byte
	for _, cert := range p.certs {
		certChain = append(certChain, cert.Raw)
	}
	sigAlg, _ := proto.EncodeSigningAlgorithm(p.keySpec.SignatureAlgorithm())
	if p.invalidSig {
		return &proto.GenerateSignatureResponse{
			KeyID:            req.KeyID,
			Signature:        invalidSignatureEnvelope,
			SigningAlgorithm: sigAlg,
			CertificateChain: certChain,
		}, err
	}
	if p.invalidCertChain {
		return &proto.GenerateSignatureResponse{
			KeyID:            req.KeyID,
			Signature:        sig,
			CertificateChain: [][]byte{{}, {}},
		}, err
	}

	return &proto.GenerateSignatureResponse{
		KeyID:            req.KeyID,
		Signature:        sig,
		CertificateChain: certChain,
	}, nil
}

// GenerateEnvelope generates the Envelope with signature based on the request.
func (p *mockPlugin) GenerateEnvelope(ctx context.Context, req *proto.GenerateEnvelopeRequest) (*proto.GenerateEnvelopeResponse, error) {
	internalPluginSigner := PluginSigner{
		plugin: newMockPlugin(p.key, p.certs, p.keySpec),
	}

	if p.failEnvelope {
		return nil, errors.New("failed GenerateEnvelope")
	}
	if p.invalidDescriptor {
		var payload map[string]interface{}
		if err := json.Unmarshal(req.Payload, &payload); err != nil {
			return nil, err
		}
		payload["additional_field"] = "some_string"

		updatedPayload, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}

		primitivePluginSigner := &pluginPrimitiveSigner{
			ctx:          ctx,
			plugin:       internalPluginSigner.plugin,
			keyID:        internalPluginSigner.keyID,
			pluginConfig: req.PluginConfig,
			keySpec:      p.keySpec,
		}

		signReq := &signature.SignRequest{
			Payload: signature.Payload{
				ContentType: envelope.MediaTypePayloadV1,
				Content:     updatedPayload,
			},
			Signer:                   primitivePluginSigner,
			SigningTime:              time.Now(),
			ExtendedSignedAttributes: nil,
			SigningScheme:            signature.SigningSchemeX509,
			SigningAgent:             "testing agent",
		}

		sigEnv, err := signature.NewEnvelope(req.SignatureEnvelopeType)
		if err != nil {
			return nil, err
		}

		sig, err := sigEnv.Sign(signReq)
		return &proto.GenerateEnvelopeResponse{
			SignatureEnvelope:     sig,
			SignatureEnvelopeType: req.SignatureEnvelopeType,
		}, err
	}
	if p.wantEnvelope {
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
			Annotations:           p.annotations,
		}, nil
	}
	return &proto.GenerateEnvelopeResponse{}, nil
}

func TestNewFromPluginFailed(t *testing.T) {
	tests := map[string]struct {
		pl     plugin.SignPlugin
		keyID  string
		errMsg string
	}{
		"Invalid KeyID": {
			pl:     &plugin.CLIPlugin{},
			keyID:  "",
			errMsg: "keyID not specified",
		},
		"nilPlugin": {
			pl:     nil,
			keyID:  "someKeyId",
			errMsg: "nil plugin",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := NewFromPlugin(tc.pl, tc.keyID, make(map[string]string))
			if err == nil || err.Error() != tc.errMsg {
				t.Fatalf("TestNewFromPluginFailed expects error %q, got %q", tc.errMsg, err.Error())
			}
		})
	}
}

func TestSigner_Sign_EnvelopeNotSupported(t *testing.T) {
	signer := PluginSigner{
		plugin: newMockPlugin(nil, nil, signature.KeySpec{Type: signature.KeyTypeRSA, Size: 2048}),
	}
	opts := notation.SignerSignOptions{SignatureMediaType: "unsupported"}
	testSignerError(t, signer, fmt.Sprintf("signature envelope format with media type %q is not supported", opts.SignatureMediaType), opts)
}

func TestSigner_Sign_DescribeKeyIDMismatch(t *testing.T) {
	respKeyId := ""
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType=%v", envelopeType), func(t *testing.T) {
			signer := PluginSigner{
				plugin: newMockPlugin(nil, nil, signature.KeySpec{}),
				keyID:  "1",
			}
			testSignerError(t, signer, fmt.Sprintf("keyID in describeKey response %q does not match request %q", respKeyId, signer.keyID), notation.SignerSignOptions{SignatureMediaType: envelopeType})
		})
	}
}

func TestSigner_Sign_ExpiryInValid(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType=%v", envelopeType), func(t *testing.T) {
			ks, _ := signature.ExtractKeySpec(keyCertPairCollections[0].certs[0])
			signer := PluginSigner{
				plugin: newMockPlugin(keyCertPairCollections[0].key, keyCertPairCollections[0].certs, ks),
			}
			_, _, err := signer.Sign(context.Background(), ocispec.Descriptor{}, notation.SignerSignOptions{ExpiryDuration: -24 * time.Hour, SignatureMediaType: envelopeType})
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
			mockPlugin := newMockPlugin(defaultKeyCert.key, defaultKeyCert.certs, defaultKeySpec)
			mockPlugin.invalidCertChain = true
			signer := PluginSigner{
				plugin: mockPlugin,
			}
			testSignerError(t, signer, "x509: malformed certificate", notation.SignerSignOptions{SignatureMediaType: envelopeType})
		})
	}
}

func TestSigner_Sign_InvalidDescriptor(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType=%v", envelopeType), func(t *testing.T) {
			mockPlugin := newMockPlugin(defaultKeyCert.key, defaultKeyCert.certs, defaultKeySpec)
			mockPlugin.wantEnvelope = true
			mockPlugin.invalidDescriptor = true
			signer := PluginSigner{
				plugin: mockPlugin,
			}
			testSignerError(t, signer, "during signing, following unknown attributes were added to subject descriptor: [\"additional_field\"]", notation.SignerSignOptions{SignatureMediaType: envelopeType})
		})
	}
}

func TestPluginSigner_Sign_SignatureVerifyError(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType=%v", envelopeType), func(t *testing.T) {
			mockPlugin := newMockPlugin(defaultKeyCert.key, defaultKeyCert.certs, defaultKeySpec)
			mockPlugin.invalidSig = true
			signer := PluginSigner{
				plugin: mockPlugin,
			}
			testSignerError(t, signer, "signature is invalid", notation.SignerSignOptions{SignatureMediaType: envelopeType})
		})
	}
}

func TestPluginSigner_Sign_Valid(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		for _, keyCert := range keyCertPairCollections {
			t.Run(fmt.Sprintf("external plugin,envelopeType=%v_keySpec=%v", envelopeType, keyCert.keySpecName), func(t *testing.T) {
				keySpec, _ := proto.DecodeKeySpec(proto.KeySpec(keyCert.keySpecName))
				pluginSigner := PluginSigner{
					plugin: newMockPlugin(keyCert.key, keyCert.certs, keySpec),
				}
				validSignOpts.SignatureMediaType = envelopeType
				data, signerInfo, err := pluginSigner.Sign(context.Background(), validSignDescriptor, validSignOpts)
				basicSignTest(t, &pluginSigner, envelopeType, data, signerInfo, err)
			})
		}
	}
}

func TestPluginSigner_SignBlob_Valid(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		for _, keyCert := range keyCertPairCollections {
			t.Run(fmt.Sprintf("external plugin,envelopeType=%v_keySpec=%v", envelopeType, keyCert.keySpecName), func(t *testing.T) {
				keySpec, _ := proto.DecodeKeySpec(proto.KeySpec(keyCert.keySpecName))
				pluginSigner := PluginSigner{
					plugin: newMockPlugin(keyCert.key, keyCert.certs, keySpec),
				}
				validSignOpts.SignatureMediaType = envelopeType
				data, signerInfo, err := pluginSigner.SignBlob(context.Background(), getDescriptorFunc(false), validSignOpts)
				basicSignTest(t, &pluginSigner, envelopeType, data, signerInfo, err)
			})
		}
	}
}

func TestPluginSigner_SignEnvelope_RunFailed(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		t.Run(fmt.Sprintf("envelopeType=%v", envelopeType), func(t *testing.T) {
			p := &mockPlugin{
				wantEnvelope: true,
				failEnvelope: true,
			}
			signer := PluginSigner{
				plugin: p,
			}
			testSignerError(t, signer, "failed GenerateEnvelope", notation.SignerSignOptions{SignatureMediaType: envelopeType})
		})
	}
}

func TestPluginSigner_SignEnvelope_Valid(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		for _, keyCert := range keyCertPairCollections {
			t.Run(fmt.Sprintf("envelopeType=%v, keySpec: %v", envelopeType, keyCert.keySpecName), func(t *testing.T) {
				keySpec, _ := proto.DecodeKeySpec(proto.KeySpec(keyCert.keySpecName))
				mockPlugin := newMockPlugin(keyCert.key, keyCert.certs, keySpec)
				mockPlugin.wantEnvelope = true
				pluginSigner := PluginSigner{
					plugin: mockPlugin,
				}
				validSignOpts.SignatureMediaType = envelopeType
				data, signerInfo, err := pluginSigner.Sign(context.Background(), validSignDescriptor, validSignOpts)
				basicSignTest(t, &pluginSigner, envelopeType, data, signerInfo, err)
			})
		}
	}
}

func TestPluginSigner_SignWithAnnotations_Valid(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		for _, keyCert := range keyCertPairCollections {
			t.Run(fmt.Sprintf("external plugin,envelopeType=%v_keySpec=%v", envelopeType, keyCert.keySpecName), func(t *testing.T) {
				keySpec, _ := proto.DecodeKeySpec(proto.KeySpec(keyCert.keySpecName))
				annts := map[string]string{"key": "value"}
				pluginSigner := PluginSigner{
					plugin: &mockPlugin{
						key:          keyCert.key,
						certs:        keyCert.certs,
						keySpec:      keySpec,
						annotations:  map[string]string{"key": "value"},
						wantEnvelope: true,
					},
				}
				validSignOpts.SignatureMediaType = envelopeType
				data, signerInfo, err := pluginSigner.Sign(context.Background(), validSignDescriptor, validSignOpts)
				basicSignTest(t, &pluginSigner, envelopeType, data, signerInfo, err)
				if !reflect.DeepEqual(pluginSigner.PluginAnnotations(), annts) {
					fmt.Println(pluginSigner.PluginAnnotations())
					t.Errorf("mismatch in annotations returned from PluginAnnotations()")
				}
			})
		}
	}
}

func testSignerError(t *testing.T, signer PluginSigner, wantEr string, opts notation.SignerSignOptions) {
	t.Helper()
	_, _, err := signer.Sign(context.Background(), ocispec.Descriptor{}, opts)
	if err == nil || !strings.Contains(err.Error(), wantEr) {
		t.Errorf("Signer.Sign() error = %v, wantErr %v", err, wantEr)
	}
}

func basicSignTest(t *testing.T, ps *PluginSigner, envelopeType string, data []byte, signerInfo *signature.SignerInfo, err error) {
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

	if err := envelope.ValidatePayloadContentType(&envContent.Payload); err != nil {
		t.Fatalf("verification failed. error = %v", err)
	}

	payload := envContent.Payload
	if payload.ContentType != envelope.MediaTypePayloadV1 {
		t.Fatalf("Signer.Sign() Payload content type changed, expect: %v, got: %v", payload.ContentType, envelope.MediaTypePayloadV1)
	}
	var gotPayload envelope.Payload
	if err := json.Unmarshal(payload.Content, &gotPayload); err != nil {
		t.Fatalf("Signer.Sign() Unmarshal payload failed: %v", err)
	}
	expectedPayload := envelope.Payload{
		TargetArtifact: validSignDescriptor,
	}
	if !reflect.DeepEqual(expectedPayload, gotPayload) {
		t.Fatalf("Signer.Sign() descriptor subject changed, expect: %+v, got: %+v", expectedPayload, payload)
	}
	if signerInfo.SignedAttributes.SigningScheme != signature.SigningSchemeX509 {
		t.Fatalf("Signer.Sign() signing scheme changed, expect: %+v, got: %+v", signerInfo.SignedAttributes.SigningScheme, signature.SigningSchemeX509)
	}
	mockPlugin := ps.plugin.(*mockPlugin)
	if mockPlugin.keySpec.SignatureAlgorithm() != signerInfo.SignatureAlgorithm {
		t.Fatalf("Signer.Sign() signing algorithm changed")
	}
	if validSignOpts.ExpiryDuration != signerInfo.SignedAttributes.Expiry.Sub(signerInfo.SignedAttributes.SigningTime) {
		t.Fatalf("Signer.Sign() expiry duration changed")
	}
	if !reflect.DeepEqual(mockPlugin.certs, signerInfo.CertificateChain) {
		t.Fatalf(" Signer.Sign() cert chain changed")
	}
	basicVerification(t, data, envelopeType, mockPlugin.certs[len(mockPlugin.certs)-1], &validMetadata)
}
