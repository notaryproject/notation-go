package jws

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/spec/v1/plugin"
	"github.com/notaryproject/notation-go/spec/v1/signature"
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
	KeySpec    signature.Key
	Sign       func(payload string) string
	SigningAlg string
	Cert       string
	n          int
}

func (s *mockSignerPlugin) Run(ctx context.Context, pluginName string, cmd plugin.Command, req interface{}) (interface{}, error) {
	var chain []string
	if s.Cert != "" {
		chain = append(chain, s.Cert)
	}
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
			CertificateChain: chain,
		}, nil
	}
	panic("too many calls")
}

func testPluginSignerError(t *testing.T, signer PluginSigner, wantEr string) {
	t.Helper()
	_, err := signer.Sign(context.Background(), signature.Descriptor{}, notation.SignOptions{})
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
	_, err := signer.Sign(context.Background(), signature.Descriptor{}, notation.SignOptions{Expiry: time.Now().Add(-100)})
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
		Runner: &mockSignerPlugin{KeyID: "2", KeySpec: signature.RSA_2048},
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
			&plugin.DescribeKeyResponse{KeyID: "1", KeySpec: signature.RSA_2048},
			&plugin.GenerateSignatureResponse{KeyID: "2"},
		}, []error{nil, nil, nil}, 0},
		KeyID: "1",
	}
	testPluginSignerError(t, signer, "keyID mismatch")
}

func TestPluginSigner_Sign_UnsuportedAlgorithm(t *testing.T) {
	signer := PluginSigner{
		Runner: &mockSignerPlugin{KeyID: "1", KeySpec: signature.RSA_2048, SigningAlg: "custom"},
		KeyID:  "1",
	}
	testPluginSignerError(t, signer, "signing algorithm \"custom\" not supported")
}

func TestPluginSigner_Sign_NoCertChain(t *testing.T) {
	signer := PluginSigner{
		Runner: &mockSignerPlugin{
			KeyID:      "1",
			KeySpec:    signature.RSA_2048,
			SigningAlg: jwt.SigningMethodES256.Alg(),
		},
		KeyID: "1",
	}
	testPluginSignerError(t, signer, "empty certificate chain")
}

func TestPluginSigner_Sign_CertNotBase64(t *testing.T) {
	signer := PluginSigner{
		Runner: &mockSignerPlugin{
			KeyID:      "1",
			KeySpec:    signature.RSA_2048,
			SigningAlg: jwt.SigningMethodES256.Alg(),
			Cert:       "r a w",
		},
		KeyID: "1",
	}
	testPluginSignerError(t, signer, "certificate not base64-encoded")
}

func TestPluginSigner_Sign_MalformedCert(t *testing.T) {
	signer := PluginSigner{
		Runner: &mockSignerPlugin{
			KeyID:      "1",
			KeySpec:    signature.RSA_2048,
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
			KeySpec:    signature.RSA_2048,
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
			KeySpec:    signature.RSA_2048,
			SigningAlg: jwt.SigningMethodES256.Alg(),
			Sign:       func(payload string) string { return base64.RawStdEncoding.EncodeToString([]byte("r a w")) },
			Cert:       base64.RawStdEncoding.EncodeToString(cert.Raw),
		},
		KeyID: "1",
	}
	testPluginSignerError(t, signer, "verification error")
}

func validSign(t *testing.T, key interface{}) func(string) string {
	t.Helper()
	return func(payload string) string {
		signed, err := jwt.SigningMethodPS256.Sign(payload, key)
		if err != nil {
			t.Fatal(err)
		}
		encSigned, err := base64.RawURLEncoding.DecodeString(signed)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawStdEncoding.EncodeToString(encSigned)
	}
}

func TestPluginSigner_Sign_CertWithoutDigitalSignatureBit(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(0),
		Subject:               pkix.Name{CommonName: "test"},
		KeyUsage:              x509.KeyUsageEncipherOnly,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	signer := PluginSigner{
		Runner: &mockSignerPlugin{
			KeyID:      "1",
			KeySpec:    signature.RSA_2048,
			SigningAlg: jwt.SigningMethodPS256.Alg(),
			Sign:       validSign(t, key),
			Cert:       base64.RawStdEncoding.EncodeToString(certBytes),
		},
		KeyID: "1",
	}
	testPluginSignerError(t, signer, "keyUsage must have the bit positions for digitalSignature set")
}

func TestPluginSigner_Sign_CertWithout_idkpcodeSigning(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(0),
		Subject:               pkix.Name{CommonName: "test"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	signer := PluginSigner{
		Runner: &mockSignerPlugin{
			KeyID:      "1",
			KeySpec:    signature.RSA_2048,
			SigningAlg: jwt.SigningMethodPS256.Alg(),
			Sign:       validSign(t, key),
			Cert:       base64.RawStdEncoding.EncodeToString(certBytes),
		},
		KeyID: "1",
	}
	testPluginSignerError(t, signer, "extKeyUsage must contain")
}

func TestPluginSigner_Sign_CertBasicConstraintCA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(0),
		Subject:               pkix.Name{CommonName: "test"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	signer := PluginSigner{
		Runner: &mockSignerPlugin{
			KeyID:      "1",
			KeySpec:    signature.RSA_2048,
			SigningAlg: jwt.SigningMethodPS256.Alg(),
			Sign:       validSign(t, key),
			Cert:       base64.RawStdEncoding.EncodeToString(certBytes),
		},
		KeyID: "1",
	}
	testPluginSignerError(t, signer, "if the basicConstraints extension is present, the CA field MUST be set false")
}

func TestPluginSigner_Sign_Valid(t *testing.T) {
	key, cert, err := generateKeyCertPair()
	if err != nil {
		t.Fatal(err)
	}
	signer := PluginSigner{
		Runner: &mockSignerPlugin{
			KeyID:      "1",
			KeySpec:    signature.RSA_2048,
			SigningAlg: jwt.SigningMethodPS256.Alg(),
			Sign:       validSign(t, key),
			Cert:       base64.RawStdEncoding.EncodeToString(cert.Raw),
		},
		KeyID: "1",
	}
	_, err = signer.Sign(context.Background(), signature.Descriptor{}, notation.SignOptions{})
	if err != nil {
		t.Errorf("PluginSigner.Sign() error = %v, wantErr nil", err)
	}
}
