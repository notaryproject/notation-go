package signature

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/notaryproject/notation-core-go/signer"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/plugin"
)

var validMetadata = plugin.Metadata{
	Name: "foo", Description: "friendly", Version: "1", URL: "example.com",
	SupportedContractVersions: []string{plugin.ContractVersion},
	Capabilities:              []plugin.Capability{plugin.CapabilitySignatureGenerator},
}

type mockRunner struct {
	resp []interface{}
	err  []error
	n    int
}

func (r *mockRunner) Run(_ context.Context, _ plugin.Request) (interface{}, error) {
	defer func() { r.n++ }()
	return r.resp[r.n], r.err[r.n]
}

type mockSignerPlugin struct {
	KeyID      string
	KeySpec    signer.KeySpec
	Sign       func(payload []byte) []byte
	Certs      [][]byte
	n          int
}

func (s *mockSignerPlugin) Run(_ context.Context, req plugin.Request) (interface{}, error) {
	if req != nil {
		// Test json roundtrip.
		jsonReq, err := json.Marshal(req)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(jsonReq, req)
		if err != nil {
			return nil, err
		}
	}
	defer func() { s.n++ }()
	switch s.n {
	case 0:
		return &validMetadata, nil
	case 1:
		return &plugin.DescribeKeyResponse{KeyID: s.KeyID, KeySpec: s.KeySpec}, nil
	case 2:
		var signed []byte
		if s.Sign != nil {
			signed = s.Sign(req.(*plugin.GenerateSignatureRequest).Payload)
		}
		return &plugin.GenerateSignatureResponse{
			KeyID:            s.KeyID,
			SigningAlgorithm: s.KeySpec.SignatureAlgorithm(),
			Signature:        signed,
			CertificateChain: s.Certs,
		}, nil
	}
	panic("too many calls")
}

func testSignerError(t *testing.T, signer pluginSigner, wantEr string) {
	t.Helper()
	_, err := signer.Sign(context.Background(), notation.Descriptor{}, notation.SignOptions{})
	if err == nil || !strings.Contains(err.Error(), wantEr) {
		t.Errorf("Signer.Sign() error = %v, wantErr %v", err, wantEr)
	}
}

func TestSigner_Sign_RunMetadataFails(t *testing.T) {
	signer := pluginSigner{
		runner: &mockRunner{[]interface{}{nil}, []error{errors.New("failed")}, 0},
	}
	testSignerError(t, signer, "metadata command failed")
}

func TestSigner_Sign_NoCapability(t *testing.T) {
	m := validMetadata
	m.Capabilities = []plugin.Capability{""}
	signer := pluginSigner{
		runner: &mockRunner{[]interface{}{&m}, []error{nil}, 0},
	}
	testSignerError(t, signer, "does not have signing capabilities")
}

func TestSigner_Sign_DescribeKeyFailed(t *testing.T) {
	signer := pluginSigner{
		runner: &mockRunner{[]interface{}{&validMetadata, nil}, []error{nil, errors.New("failed")}, 0},
	}
	testSignerError(t, signer, "describe-key command failed")
}

func TestSigner_Sign_DescribeKeyKeyIDMismatch(t *testing.T) {
	signer := pluginSigner{
		runner: &mockSignerPlugin{KeyID: "2", KeySpec: signer.RSA_2048},
		keyID:  "1",
	}
	testSignerError(t, signer, "keyID in describeKey response \"2\" does not match request \"1\"")
}

func TestSigner_Sign_KeySpecNotSupported(t *testing.T) {
	signer := pluginSigner{
		runner: &mockSignerPlugin{KeyID: "1", KeySpec: "custom"},
		keyID:  "1",
	}
	testSignerError(t, signer, "signature algorithm \"\" is not supported")
}

func TestSigner_Sign_PayloadNotValid(t *testing.T) {
	signer := pluginSigner{
		runner: &mockRunner{[]interface{}{
			&validMetadata,
			&plugin.DescribeKeyResponse{KeyID: "1", KeySpec: signer.RSA_2048},
		}, []error{nil, nil}, 0},
		keyID: "1",
	}
	_, err := signer.Sign(context.Background(), notation.Descriptor{}, notation.SignOptions{Expiry: time.Now().Add(-100)})
	wantEr := "expiry cannot be equal or before the signing time"
	if err == nil || !strings.Contains(err.Error(), wantEr) {
		t.Errorf("Signer.Sign() error = %v, wantErr %v", err, wantEr)
	}
}

func TestSigner_Sign_GenerateSignatureKeyIDMismatch(t *testing.T) {
	signer := pluginSigner{
		runner: &mockRunner{[]interface{}{
			&validMetadata,
			&plugin.DescribeKeyResponse{KeyID: "1", KeySpec: signer.RSA_2048},
			&plugin.GenerateSignatureResponse{KeyID: "2"},
		}, []error{nil, nil, nil}, 0},
		keyID: "1",
	}
	testSignerError(t, signer, "keyID in generateSignature response \"2\" does not match request \"1\"")
}

func TestSigner_Sign_UnsuportedKeySpec(t *testing.T) {
	_, cert, _ := generateKeyCertPair()
	signer := pluginSigner{
		runner: &mockSignerPlugin{KeyID: "1", KeySpec: "", Certs: getBytes(cert)},
		keyID:  "1",
	}
	testSignerError(t, signer, "signature algorithm \"\" is not supported")
}

func TestSigner_Sign_NoCertChain(t *testing.T) {
	signer := pluginSigner{
		runner: &mockSignerPlugin{
			KeyID:      "1",
			KeySpec:    signer.RSA_2048,
		},
		keyID: "1",
	}
	testSignerError(t, signer, "certificate-chain not present or is empty")
}

func TestSigner_Sign_MalformedCert(t *testing.T) {
	signer := pluginSigner{
		runner: &mockSignerPlugin{
			KeyID:      "1",
			KeySpec:    signer.RSA_2048,
			Certs:      [][]byte{[]byte("mocked")},
		},
		keyID: "1",
	}
	testSignerError(t, signer, "x509: malformed certificate")
}

func TestSigner_Sign_SignatureVerifyError(t *testing.T) {
	_, cert, err := generateKeyCertPair()
	if err != nil {
		t.Fatalf("generateKeyCertPair() error = %v", err)
	}
	signer := pluginSigner{
		runner: &mockSignerPlugin{
			KeyID:   "1",
			KeySpec: signer.RSA_2048,
			Sign:    func(payload []byte) []byte { return []byte("r a w") },
			Certs:   getBytes(cert),
		},
		keyID: "1",
	}
	testSignerError(t, signer, "signature returned by generateSignature cannot be verified")
}

func validSign(t *testing.T, key interface{}) func([]byte) []byte {
	t.Helper()
	return func(payload []byte) []byte {
		signed, err := jwt.SigningMethodPS256.Sign(string(payload), key)
		if err != nil {
			t.Fatal(err)
		}
		encSigned, err := base64.RawURLEncoding.DecodeString(signed)
		if err != nil {
			t.Fatal(err)
		}
		return encSigned
	}
}

func TestSigner_Sign_Valid(t *testing.T) {
	key, cert, err := generateKeyCertPair()
	if err != nil {
		t.Fatal(err)
	}
	pluginSigner := pluginSigner{
		runner: &mockSignerPlugin{
			KeyID:   "1",
			KeySpec: signer.RSA_2048,
			Sign:    validSign(t, key),
			Certs:   getBytes(cert),
		},
		keyID: "1",
	}
	data, err := pluginSigner.Sign(context.Background(), notation.Descriptor{}, notation.SignOptions{})
	if err != nil {
		t.Errorf("Signer.Sign() error = %v, wantErr nil", err)
	}

	env, err := signer.NewSignatureEnvelopeFromBytes(data, signer.MediaTypeJWSJson)
	if err != nil {
		t.Fatal(err)
	}
	sigInfo, err := env.Verify()
	if err != nil {
		t.Fatal(err)
	}

	expectedPayload := notation.Payload{
		TargetArtifact: notation.Descriptor{},
	}
	expectPayloadBytes, err := json.Marshal(expectedPayload)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(sigInfo.Payload, expectPayloadBytes) {
		t.Errorf("Signer.Sign() payload changed")
	}


	if !reflect.DeepEqual(sigInfo.CertificateChain, cert) {
		t.Errorf("Signer.Sign() cert chain changed")
	}

	basicVerification(data, cert[len(cert)-1], t)
}

type mockEnvelopePlugin struct {
	err          error
	envelopeType string
	certChain    [][]byte
	key          interface{}
}

func (s *mockEnvelopePlugin) Run(_ context.Context, req plugin.Request) (interface{}, error) {
	switch req.Command() {
	case plugin.CommandGetMetadata:
		m := validMetadata
		m.Capabilities[0] = plugin.CapabilityEnvelopeGenerator
		return &m, nil
	case plugin.CommandGenerateEnvelope:
		if s.err != nil {
			return nil, s.err
		}
		key, certs, err := generateKeyCertPair()
		if err != nil {
			return nil, err
		}
		if s.key != nil {
			key = s.key
		}

		var resolvedCertChain []*x509.Certificate
		if s.certChain != nil {
			// Override cert chain.
			resolvedCertChain, err = parseCertChain(s.certChain)
			if err != nil {
				return nil, err
			}
		} else {
			resolvedCertChain = certs
		}
		lsp, err := signer.GetLocalSignatureProvider(resolvedCertChain, key)
		if err != nil {
			return nil, err
		}
		env, _ := signer.NewSignatureEnvelope(signer.MediaTypeJWSJson)

		req1 := req.(*plugin.GenerateEnvelopeRequest)

		data, err := env.Sign(signer.SignRequest{
			Payload:             req1.Payload,
			PayloadContentType:  signer.PayloadContentType(req1.PayloadType),
			SignatureProvider:   lsp,
			SigningTime:         time.Now(),
			Expiry:              time.Now().AddDate(2,0,0),
			SigningAgent:        "",
		})
		if err != nil {
			return nil, err
		}

		envType := s.envelopeType
		if envType == "" {
			envType = req1.SignatureEnvelopeType
		}
		return &plugin.GenerateEnvelopeResponse{
			SignatureEnvelope:     data,
			SignatureEnvelopeType: envType,
		}, nil
	}
	panic("too many calls")
}
func TestPluginSigner_SignEnvelope_RunFailed(t *testing.T) {
	signer := pluginSigner{
		runner: &mockEnvelopePlugin{err: errors.New("failed")},
		keyID:  "1",
	}
	_, err := signer.Sign(context.Background(), notation.Descriptor{
		MediaType: notation.MediaTypePayload,
		Size:      1,
	}, notation.SignOptions{})
	if err == nil || err.Error() != "generate-envelope command failed: failed" {
		t.Errorf("Signer.Sign() error = %v, wantErr nil", err)
	}
}

func TestPluginSigner_SignEnvelope_InvalidEnvelopeType(t *testing.T) {
	signer := pluginSigner{
		runner: &mockEnvelopePlugin{envelopeType: "other"},
		keyID:  "1",
	}
	_, err := signer.Sign(context.Background(), notation.Descriptor{
		MediaType: notation.MediaTypePayload,
		Size:      1,
	}, notation.SignOptions{})
	if err == nil || err.Error() != "signatureEnvelopeType in generateEnvelope response \"other\" does not match request \"application/jose+json\"" {
		t.Errorf("Signer.Sign() error = %v, wantErr nil", err)
	}
}

func TestPluginSigner_SignEnvelope_EmptyCert(t *testing.T) {
	signer := pluginSigner{
		runner: &mockEnvelopePlugin{certChain: [][]byte{}},
		keyID:  "1",
	}
	_, err := signer.Sign(context.Background(), notation.Descriptor{
		MediaType: notation.MediaTypePayload,
		Size:      1,
	}, notation.SignOptions{})
	if err == nil || err.Error() != "generate-envelope command failed: \"certs\" param is malformed" {
		t.Errorf("Signer.Sign() error = %v, wantErr nil", err)
	}
}

func TestPluginSigner_SignEnvelope_MalformedCertChain(t *testing.T) {
	signer := pluginSigner{
		runner: &mockEnvelopePlugin{certChain: [][]byte{make([]byte, 0)}},
		keyID:  "1",
	}
	_, err := signer.Sign(context.Background(), notation.Descriptor{
		MediaType: notation.MediaTypePayload,
		Size:      1,
	}, notation.SignOptions{})
	if err == nil || err.Error() != "generate-envelope command failed: x509: malformed certificate" {
		t.Errorf("Signer.Sign() error = %v, wantErr nil", err)
	}
}

func TestPluginSigner_SignEnvelope_SignatureVerifyError(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer := pluginSigner{
		runner: &mockEnvelopePlugin{key: key},
		keyID:  "1",
	}
	_, err = signer.Sign(context.Background(), notation.Descriptor{
		MediaType: notation.MediaTypePayload,
		Size:      1,
	}, notation.SignOptions{})
	if err == nil || err.Error() != "signature is invalid. Error: crypto/rsa: verification error" {
		t.Errorf("Signer.Sign() error = %v, wantErr nil", err)
	}
}

func TestPluginSigner_SignEnvelope_Valid(t *testing.T) {
	signer := pluginSigner{
		runner: &mockEnvelopePlugin{},
		keyID:  "1",
	}
	_, err := signer.Sign(context.Background(), notation.Descriptor{
		MediaType: notation.MediaTypePayload,
		Size:      1,
	}, notation.SignOptions{})
	if err != nil {
		t.Errorf("Signer.Sign() error = %v, wantErr nil", err)
	}
}

func getBytes(certs []*x509.Certificate) [][]byte {
	var chain [][]byte
	for _, cert := range certs {
		chain = append(chain, cert.Raw)
	}
	return chain
}
