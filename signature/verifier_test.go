package signature

import (
	"context"
	"crypto/x509"
	"reflect"
	"testing"

	"github.com/notaryproject/notation-go"
)

func TestVerifierInterface(t *testing.T) {
	if _, ok := interface{}(&Verifier{}).(notation.Verifier); !ok {
		t.Error("&Verifier{} does not conform notation.Verifier")
	}
}

func TestVerifyWithCertChain(t *testing.T) {
	// sign with key
	key, cert, err := generateKeyCertPair()
	if err != nil {
		t.Fatalf("generateKeyCertPair() error = %v", err)
	}
	s, err := NewSigner(key, cert)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	ctx := context.Background()
	desc, sOpts := generateSigningContent(nil)
	sig, err := s.Sign(ctx, desc, sOpts)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// verify signature
	v := NewVerifier()
	var vOpts notation.VerifyOptions

	// should fail if nothing is trusted
	if _, err := v.Verify(ctx, sig, vOpts); err == nil {
		t.Errorf("Verify() error = %v, wantErr %v", err, true)
	}

	// verify again with certificate trusted
	v.TrustedCerts = []*x509.Certificate{cert[len(cert)-1]}
	got, err := v.Verify(ctx, sig, vOpts)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !got.Equal(desc) {
		t.Errorf("Verify() Descriptor = %v, want %v", got, desc)
	}
	if !reflect.DeepEqual(got, desc) {
		t.Errorf("Verify() Descriptor = %v, want %v", got, desc)
	}
}

func TestVerifyWithTimestamp(t *testing.T) {
	t.Skip("Skipping testing as we dont have timestamping hooked up")
	// prepare signer
	// key, cert, err := generateKeyCertPair()
	// if err != nil {
	// 	t.Fatalf("generateKeyCertPair() error = %v", err)
	// }
	// s, err := NewSigner(key, cert)
	// if err != nil {
	// 	t.Fatalf("NewSigner() error = %v", err)
	// }
	//
	// // configure TSA
	// tsa, err := timestamptest.NewTSA()
	// if err != nil {
	// 	t.Fatalf("timestamptest.NewTSA() error = %v", err)
	// }
	//
	// // sign content
	// ctx := context.Background()
	// desc, sOpts := generateSigningContent(tsa)
	// sig, err := s.Sign(ctx, desc, sOpts)
	// if err != nil {
	// 	t.Fatalf("Sign() error = %v", err)
	// }
	//
	// // verify signature
	// v := NewVerifier()
	// roots := x509.NewCertPool()
	// roots.AddCert(cert[len(cert)-1])
	// v.VerifyOptions.Roots = roots
	//
	// // should fail if TSA is trusted when signature certificate is expired.
	// v.VerifyOptions.CurrentTime = time.Now().Add(48 * time.Hour)
	// var vOpts notation.VerifyOptions
	// if _, err := v.Verify(ctx, sig, vOpts); err == nil {
	// 	t.Errorf("Verify() error = %v, wantErr %v", err, true)
	// }
	//
	// // verify again with certificate trusted
	// v.TSARoots = sOpts.TSAVerifyOptions.Roots
	// got, err := v.Verify(ctx, sig, vOpts)
	// if err != nil {
	// 	t.Fatalf("Verify() error = %v", err)
	// }
	// if !got.Equal(desc) {
	// 	t.Errorf("Verify() Descriptor = %v, want %v", got, desc)
	// }
	// if !reflect.DeepEqual(got, desc) {
	// 	t.Errorf("Verify() Descriptor = %v, want %v", got, desc)
	// }
}
