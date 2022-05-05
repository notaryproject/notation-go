package jws

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/plugin"
)

type mockRunner struct {
	resp []interface{}
	err  []error
	n    int
}

func (r *mockRunner) Run(ctx context.Context, pluginName string, cmd plugin.Command, req interface{}) (interface{}, error) {
	defer func() { r.n++ }()
	return r.resp[r.n], r.err[r.n]
}

type mockSignerPlugin struct {
	KeyID      string
	KeySpec    plugin.KeySpec
	Sign       func(payload string) string
	SigningAlg string
	Cert       string
	n          int
}

func (s *mockSignerPlugin) Run(ctx context.Context, pluginName string, cmd plugin.Command, req interface{}) (interface{}, error) {
	defer func() { s.n++ }()
	switch s.n {
	case 0:
		return &plugin.Metadata{Capabilities: []plugin.Capability{plugin.CapabilitySignatureGenerator}}, nil
	case 1:
		return &plugin.DescribeKeyResponse{KeyID: s.KeyID, KeySpec: s.KeySpec}, nil
	case 2:
		var signed string
		if s.Sign != nil {
			signed = s.Sign(req.(*plugin.GenerateSignatureRequest).Payload)
		}
		return &plugin.GenerateSignatureResponse{
			KeyID:            s.KeyID,
			SigningAlgorithm: s.SigningAlg,
			Signature:        signed,
			CertificateChain: []string{s.Cert},
		}, nil
	}
	panic("too many calls")
}

func testPluginSignerError(t *testing.T, signer PluginSigner, wantEr string) {
	t.Helper()
	_, err := signer.Sign(context.Background(), notation.Descriptor{}, notation.SignOptions{})
	if err == nil || !strings.Contains(err.Error(), wantEr) {
		t.Errorf("PluginSigner.Sign() error = %v, wantErr %v", err, wantEr)
	}
}

func TestPluginSigner_Sign_RunMetadataFails(t *testing.T) {
	signer := PluginSigner{
		Runner: &mockRunner{[]interface{}{nil}, []error{errors.New("failed")}, 0},
	}
	testPluginSignerError(t, signer, "metadata command failed")
}

func TestPluginSigner_Sign_PayloadNotValid(t *testing.T) {
	signer := PluginSigner{
		Runner: &mockRunner{[]interface{}{
			&plugin.Metadata{Capabilities: []plugin.Capability{plugin.CapabilitySignatureGenerator}},
		}, []error{nil}, 0},
	}
	_, err := signer.Sign(context.Background(), notation.Descriptor{}, notation.SignOptions{Expiry: time.Now().Add(-100)})
	wantEr := "token is expired"
	if err == nil || !strings.Contains(err.Error(), wantEr) {
		t.Errorf("PluginSigner.Sign() error = %v, wantErr %v", err, wantEr)
	}
}

func TestPluginSigner_Sign_NoCapability(t *testing.T) {
	signer := PluginSigner{
		Runner: &mockRunner{[]interface{}{
			&plugin.Metadata{Capabilities: []plugin.Capability{}},
		}, []error{nil}, 0},
	}
	testPluginSignerError(t, signer, "does not have signing capabilities")
}

func TestPluginSigner_Sign_DescribeKeyFailed(t *testing.T) {
	signer := PluginSigner{
		Runner: &mockRunner{[]interface{}{
			&plugin.Metadata{Capabilities: []plugin.Capability{plugin.CapabilitySignatureGenerator}},
			nil,
		}, []error{nil, errors.New("failed")}, 0},
	}
	testPluginSignerError(t, signer, "describe-key command failed")
}

func TestPluginSigner_Sign_DescribeKeyKeyIDMismatch(t *testing.T) {
	signer := PluginSigner{
		Runner: &mockSignerPlugin{KeyID: "2", KeySpec: plugin.RSA_2048},
		KeyID:  "1",
	}
	testPluginSignerError(t, signer, "keyID mismatch")
}

func TestPluginSigner_Sign_KeySpecNotSupported(t *testing.T) {
	signer := PluginSigner{
		Runner: &mockSignerPlugin{KeyID: "1", KeySpec: "custom"},
		KeyID:  "1",
	}
	testPluginSignerError(t, signer, "keySpec \"custom\" not supported")
}

func TestPluginSigner_Sign_GenerateSignatureKeyIDMismatch(t *testing.T) {
	signer := PluginSigner{
		Runner: &mockRunner{[]interface{}{
			&plugin.Metadata{Capabilities: []plugin.Capability{plugin.CapabilitySignatureGenerator}},
			&plugin.DescribeKeyResponse{KeyID: "1", KeySpec: plugin.RSA_2048},
			&plugin.GenerateSignatureResponse{KeyID: "2"},
		}, []error{nil, nil, nil}, 0},
		KeyID: "1",
	}
	testPluginSignerError(t, signer, "keyID mismatch")
}

func TestPluginSigner_Sign_UnsuportedAlgorithm(t *testing.T) {
	signer := PluginSigner{
		Runner: &mockSignerPlugin{KeyID: "1", KeySpec: plugin.RSA_2048, SigningAlg: "custom"},
		KeyID:  "1",
	}
	testPluginSignerError(t, signer, "signing algorithm \"custom\" not supported")
}

func TestPluginSigner_Sign_CertNotBase64(t *testing.T) {
	signer := PluginSigner{
		Runner: &mockSignerPlugin{
			KeyID:      "1",
			KeySpec:    plugin.RSA_2048,
			SigningAlg: jwt.SigningMethodES256.Alg(), Cert: "r a w",
		},
		KeyID: "1",
	}
	testPluginSignerError(t, signer, "certificate not base64-encoded")
}

func TestPluginSigner_Sign_InvalidCert(t *testing.T) {
	signer := PluginSigner{
		Runner: &mockSignerPlugin{
			KeyID:      "1",
			KeySpec:    plugin.RSA_2048,
			SigningAlg: jwt.SigningMethodES256.Alg(),
			Cert:       base64.RawStdEncoding.EncodeToString([]byte("mocked")),
		},
		KeyID: "1",
	}
	testPluginSignerError(t, signer, "x509: malformed certificate")
}

func TestPluginSigner_Sign_SignatureNotBase64(t *testing.T) {
	_, cert, err := generateKeyCertPair()
	if err != nil {
		t.Fatalf("generateKeyCertPair() error = %v", err)
	}
	signer := PluginSigner{
		Runner: &mockSignerPlugin{
			KeyID:      "1",
			KeySpec:    plugin.RSA_2048,
			SigningAlg: jwt.SigningMethodES256.Alg(),
			Sign:       func(payload string) string { return "r a w" },
			Cert:       base64.RawStdEncoding.EncodeToString(cert.Raw),
		},
		KeyID: "1",
	}
	testPluginSignerError(t, signer, "signature not base64-encoded")
}

func TestPluginSigner_Sign_SignatureVerifyError(t *testing.T) {
	_, cert, err := generateKeyCertPair()
	if err != nil {
		t.Fatalf("generateKeyCertPair() error = %v", err)
	}
	signer := PluginSigner{
		Runner: &mockSignerPlugin{
			KeyID:      "1",
			KeySpec:    plugin.RSA_2048,
			SigningAlg: jwt.SigningMethodES256.Alg(),
			Sign:       func(payload string) string { return base64.RawStdEncoding.EncodeToString([]byte("r a w")) },
			Cert:       base64.RawStdEncoding.EncodeToString(cert.Raw),
		},
		KeyID: "1",
	}
	testPluginSignerError(t, signer, "verification error")
}

func TestPluginSigner_Sign_Valid(t *testing.T) {
	key, cert, err := generateKeyCertPair()
	if err != nil {
		t.Fatal(err)
	}
	signer := PluginSigner{
		Runner: &mockSignerPlugin{
			KeyID:      "1",
			KeySpec:    plugin.RSA_2048,
			SigningAlg: jwt.SigningMethodPS256.Alg(),
			Sign: func(payload string) string {
				signed, err := jwt.SigningMethodPS256.Sign(payload, key)
				if err != nil {
					t.Fatal(err)
				}
				encSigned, err := base64.RawURLEncoding.DecodeString(signed)
				if err != nil {
					t.Fatal(err)
				}
				return base64.RawStdEncoding.EncodeToString(encSigned)
			},
			Cert: base64.RawStdEncoding.EncodeToString(cert.Raw),
		},
		KeyID: "1",
	}
	_, err = signer.Sign(context.Background(), notation.Descriptor{}, notation.SignOptions{})
	if err != nil {
		t.Errorf("PluginSigner.Sign() error = %v, wantErr nil", err)
	}
}
