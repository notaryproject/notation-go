package jws

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
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

func testSignWithCertChain(t *testing.T, key crypto.PrivateKey) {
	cert, err := generateCert(key)
	if err != nil {
		t.Fatal(err)
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

func TestSignWithCertChain(t *testing.T) {
	// sign with key
	tests := []struct {
		name string
		fn   func() (crypto.PrivateKey, error)
	}{
		{
			name: string(notation.RSA_2048),
			fn:   func() (crypto.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) },
		},
		{
			name: string(notation.RSA_3072),
			fn:   func() (crypto.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 3072) },
		},
		{
			name: string(notation.RSA_4096),
			fn:   func() (crypto.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 4096) },
		},
		{
			name: string(notation.EC_256),
			fn:   func() (crypto.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) },
		},
		{
			name: string(notation.EC_384),
			fn:   func() (crypto.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P384(), rand.Reader) },
		},
		{
			name: string(notation.EC_512),
			fn:   func() (crypto.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P521(), rand.Reader) },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key, err := test.fn()
			if err != nil {
				t.Fatal(err)
			}
			testSignWithCertChain(t, key)
		})
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

func generateKeyCertPair() (crypto.PrivateKey, *x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	cert, err := generateCert(key)
	return key, cert, err
}

// generateKeyCertPair generates a test key / certificate pair.
func generateCert(key crypto.PrivateKey) (*x509.Certificate, error) {
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, err
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
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, key.(crypto.Signer).Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
