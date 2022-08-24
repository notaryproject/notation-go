package signature

import (
	"context"
	"crypto/x509"
	"fmt"
	"reflect"
	"testing"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go"
)

func TestVerifierInterface(t *testing.T) {
	if _, ok := interface{}(&Verifier{}).(notation.Verifier); !ok {
		t.Error("&Verifier{} does not conform notation.Verifier")
	}
}

func testVerifierFromFile(t *testing.T, keyCert *keyCertPair, envelopeType, dir string) {
	keyPath, certPath, err := prepareTestKeyCertFile(keyCert, envelopeType, dir)
	if err != nil {
		t.Fatalf("prepare key cert file failed: %v", err)
	}
	s, err := NewSignerFromFiles(keyPath, certPath, envelopeType)
	if err != nil {
		t.Fatalf("NewSignerFromFiles() failed: %v", err)
	}
	desc, opts := generateSigningContent(nil)
	sig, err := s.Sign(context.Background(), desc, opts)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}
	// verify signature
	v, err := NewVerifierFromFiles([]string{certPath})
	if err != nil {
		t.Fatalf("NewVerifierFromFiles() failed: %v", err)
	}
	vOpts := notation.VerifyOptions{
		SignatureMediaType: envelopeType,
	}
	got, err := v.Verify(context.Background(), sig, vOpts)
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

func TestNewVerifierFromFile(t *testing.T) {
	dir := t.TempDir()
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		for _, keyCert := range keyCertPairCollections {
			t.Run(fmt.Sprintf("envelopeType:%v,keySpec:%v", envelopeType, keyCert.keySpecName), func(t *testing.T) {
				testVerifierFromFile(t, keyCert, envelopeType, dir)
			})
		}
	}
}

func TestVerifyWithCertChain(t *testing.T) {
	// sign with key
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		for _, keyCert := range keyCertPairCollections {
			t.Run(fmt.Sprintf("envelopeType:%v,keySpec:%v", envelopeType, keyCert.keySpecName), func(t *testing.T) {
				s, err := NewSigner(keyCert.key, keyCert.certs, envelopeType)
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
				vOpts := notation.VerifyOptions{
					SignatureMediaType: envelopeType,
				}

				// should fail if nothing is trusted
				if _, err := v.Verify(ctx, sig, vOpts); err == nil {
					t.Errorf("Verify() error = %v, wantErr %v", err, true)
				}

				// verify again with certificate trusted
				v.TrustedCerts = []*x509.Certificate{keyCert.certs[len(keyCert.certs)-1]}
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
			})
		}
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
