package jws

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/crypto/timestamp/timestamptest"
	"github.com/opencontainers/go-digest"
)

func TestSignerInterface(t *testing.T) {
	if _, ok := interface{}(&Signer{}).(notation.Signer); !ok {
		t.Error("&Signer{} does not conform notation.Signer")
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
	desc, sOpts := generateSigningContent(nil)
	sig, err := s.Sign(ctx, desc, sOpts)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// basic verification
	v := NewVerifier()
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	v.VerifyOptions.Roots = roots
	if _, err := v.Verify(ctx, sig, notation.VerifyOptions{}); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestSignWithTimestamp(t *testing.T) {
	// prepare signer
	key, cert, err := generateKeyCertPair()
	if err != nil {
		t.Fatalf("generateKeyCertPair() error = %v", err)
	}
	s, err := NewSigner(key, []*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	// configure TSA
	tsa, err := timestamptest.NewTSA()
	if err != nil {
		t.Fatalf("timestamptest.NewTSA() error = %v", err)
	}
	s.TSA = tsa
	tsaRoots := x509.NewCertPool()
	tsaRoots.AddCert(tsa.Certificate())
	s.TSARoots = tsaRoots

	// sign content
	ctx := context.Background()
	desc, sOpts := generateSigningContent(tsa)
	sig, err := s.Sign(ctx, desc, sOpts)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// basic verification
	v := NewVerifier()
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	v.VerifyOptions.Roots = roots
	if _, err := v.Verify(ctx, sig, notation.VerifyOptions{}); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestSignWithoutExpiry(t *testing.T) {
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
	desc, sOpts := generateSigningContent(nil)
	sOpts.Expiry = time.Time{} // reset expiry
	sig, err := s.Sign(ctx, desc, sOpts)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// basic verification
	v := NewVerifier()
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	v.VerifyOptions.Roots = roots
	if _, err := v.Verify(ctx, sig, notation.VerifyOptions{}); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

// generateSigningContent generates common signing content with options for testing.
func generateSigningContent(tsa *timestamptest.TSA) (notation.Descriptor, notation.SignOptions) {
	content := "hello world"
	desc := notation.Descriptor{
		MediaType: "test media type",
		Digest:    digest.Canonical.FromString(content),
		Size:      int64(len(content)),
		Annotations: map[string]string{
			"identity": "test.registry.io/test:example",
			"foo":      "bar",
		},
	}
	now := time.Now().UTC()
	sOpts := notation.SignOptions{
		Expiry: now.Add(time.Hour),
	}
	if tsa != nil {
		sOpts.TSA = tsa
		tsaRoots := x509.NewCertPool()
		tsaRoots.AddCert(tsa.Certificate())
		sOpts.TSAVerifyOptions.Roots = tsaRoots
	}
	return desc, sOpts
}

// generateKeyCertPair generates a test key / certificate pair.
func generateKeyCertPair() (*rsa.PrivateKey, *x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
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
