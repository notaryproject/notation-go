package jws

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/notaryproject/notation-go-lib"
	"github.com/opencontainers/go-digest"
)

func TestSignerInterface(t *testing.T) {
	if _, ok := interface{}(&Signer{}).(notation.Signer); !ok {
		t.Error("&Signer{} does not conform notation.Signer")
	}
}

func TestSignWithPlainKey(t *testing.T) {
	// generate a RSA key pair
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	keyID := "test key"

	// sign with key
	method, err := SigningMethodFromKey(key)
	if err != nil {
		t.Fatalf("SigningMethodFromKey() error = %v", err)
	}
	s, err := NewSignerWithKeyID(method, key, keyID)
	if err != nil {
		t.Fatalf("NewSignerWithKeyID() error = %v", err)
	}

	ctx := context.Background()
	desc, sOpts := generateSigningContent()
	sig, err := s.Sign(ctx, desc, sOpts)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// basic verification
	vk, err := NewVerificationKey(key.Public(), keyID)
	if err != nil {
		t.Fatalf("NewVerificationKey() error = %v", err)
	}
	v := NewVerifier([]*VerificationKey{vk})
	if _, _, err := v.Verify(ctx, sig, notation.VerifyOptions{}); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestSignWithCertChain(t *testing.T) {
	// sign with key
	key, cert, err := generateKeyCertPair()
	if err != nil {
		t.Fatalf("generateKeyCertPair() error = %v", err)
	}
	s, err := NewSigner(key, []*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	ctx := context.Background()
	desc, sOpts := generateSigningContent()
	sig, err := s.Sign(ctx, desc, sOpts)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// basic verification
	v := NewVerifier(nil)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	v.VerifyOptions.Roots = roots
	if _, _, err := v.Verify(ctx, sig, notation.VerifyOptions{}); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

// generateSigningContent generates common signing content with options for testing.
func generateSigningContent() (notation.Descriptor, notation.SignOptions) {
	content := "hello world"
	desc := notation.Descriptor{
		MediaType: "test media type",
		Digest:    digest.Canonical.FromString(content),
		Size:      int64(len(content)),
	}
	now := time.Now().UTC()
	sOpts := notation.SignOptions{
		Expiry: now.Add(time.Hour),
		Metadata: notation.Metadata{
			Identity: "test.registry.io/test:example",
			Attributes: map[string]interface{}{
				"foo": "bar",
			},
		},
	}
	return desc, sOpts
}

// generateKeyCertPair generates a test key / certificate pair.
func generateKeyCertPair() (*rsa.PrivateKey, *x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore:             now,
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}
