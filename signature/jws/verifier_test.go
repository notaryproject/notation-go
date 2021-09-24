package jws

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"reflect"
	"testing"
	"time"

	"github.com/notaryproject/notation-go-lib"
	"github.com/notaryproject/notation-go-lib/crypto/timestamp/timestamptest"
)

func TestVerifierInterface(t *testing.T) {
	if _, ok := interface{}(&Verifier{}).(notation.Verifier); !ok {
		t.Error("&Verifier{} does not conform notation.Verifier")
	}
}

func TestVerifyWithPlainKey(t *testing.T) {
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

	// verify signature
	vk, err := NewVerificationKey(key.Public(), keyID)
	if err != nil {
		t.Fatalf("NewVerificationKey() error = %v", err)
	}
	v := NewVerifier([]*VerificationKey{vk})
	var vOpts notation.VerifyOptions
	got, meta, err := v.Verify(ctx, sig, vOpts)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if got != desc {
		t.Errorf("Verify() Descriptor = %v, want %v", got, desc)
	}
	if !reflect.DeepEqual(meta, sOpts.Metadata) {
		t.Errorf("Verify() Metadata = %v, want %v", meta, sOpts.Metadata)
	}

	// should fail if a different key is used
	key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	vk, err = NewVerificationKey(key.Public(), keyID)
	if err != nil {
		t.Fatalf("NewVerificationKey() error = %v", err)
	}
	v = NewVerifier([]*VerificationKey{vk})
	if _, _, err := v.Verify(ctx, sig, vOpts); err == nil {
		t.Errorf("Verify() error = %v, wantErr %v", err, true)
	}
}

func TestVerifyWithCertChain(t *testing.T) {
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

	// verify signature
	v := NewVerifier(nil)
	var vOpts notation.VerifyOptions

	// should fail if nothing is trusted
	if _, _, err := v.Verify(ctx, sig, vOpts); err == nil {
		t.Errorf("Verify() error = %v, wantErr %v", err, true)
	}

	// verify again with certificate trusted
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	v.VerifyOptions.Roots = roots
	got, meta, err := v.Verify(ctx, sig, vOpts)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if got != desc {
		t.Errorf("Verify() Descriptor = %v, want %v", got, desc)
	}
	if !reflect.DeepEqual(meta, sOpts.Metadata) {
		t.Errorf("Verify() Metadata = %v, want %v", meta, sOpts.Metadata)
	}
}

func TestVerifyWithTimestamp(t *testing.T) {
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
	s.TSAVerifyOptions.Roots = tsaRoots

	// sign content
	ctx := context.Background()
	desc, sOpts := generateSigningContent()
	sig, err := s.Sign(ctx, desc, sOpts)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// verify signature
	v := NewVerifier(nil)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	v.VerifyOptions.Roots = roots

	// should fail if TSA is trusted when signature certificate is expired.
	v.VerifyOptions.CurrentTime = time.Now().Add(48 * time.Hour)
	var vOpts notation.VerifyOptions
	if _, _, err := v.Verify(ctx, sig, vOpts); err == nil {
		t.Errorf("Verify() error = %v, wantErr %v", err, true)
	}

	// verify again with certificate trusted
	v.TSAVerifyOptions.Roots = tsaRoots
	got, meta, err := v.Verify(ctx, sig, vOpts)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if got != desc {
		t.Errorf("Verify() Descriptor = %v, want %v", got, desc)
	}
	if !reflect.DeepEqual(meta, sOpts.Metadata) {
		t.Errorf("Verify() Metadata = %v, want %v", meta, sOpts.Metadata)
	}
}
