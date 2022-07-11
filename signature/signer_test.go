package signature

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/signer"
	"github.com/notaryproject/notation-core-go/testhelper"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/crypto/timestamp/timestamptest"
	"github.com/opencontainers/go-digest"
)

func TestNewSignerFromFiles(t *testing.T) {
	t.Skip("Please implement TestNewSignerFromFiles test")
}

func TestSignWithCertChain(t *testing.T) {
	// sign with key
	rsaRoot := testhelper.GetRSARootCertificate()
	for _, k := range []int{2048, 3072, 4096} {
		pk, _ := rsa.GenerateKey(rand.Reader, k)
		certTuple := testhelper.GetRSACertTupleWithPK(pk, "TestSignWithCertChain_"+strconv.Itoa(pk.Size()), &rsaRoot)
		t.Run(fmt.Sprintf("RSA certificates of size %d", pk.Size()), func(t *testing.T) {
			validateSignWithCerts(t, pk, []*x509.Certificate{certTuple.Cert, rsaRoot.Cert})
		})
	}

	ecRoot := testhelper.GetECRootCertificate()
	for _, v := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		pk, _ := ecdsa.GenerateKey(v, rand.Reader)
		certTuple := testhelper.GetECDSACertTupleWithPK(pk, "TestSignWithCertChain_"+strconv.Itoa(pk.Params().BitSize), &ecRoot)
		t.Run(fmt.Sprintf("EC certificates of size %d", pk.Params().BitSize), func(t *testing.T) {
			validateSignWithCerts(t, pk, []*x509.Certificate{certTuple.Cert, ecRoot.Cert})
		})
	}
}

// TODO: Enable once we have timestamping inplace https://github.com/notaryproject/notation-go/issues/78
func TestSignWithTimestamp(t *testing.T) {
	t.Skip("Skipping testing as we dont have timestamping hooked up")
	// prepare signer
	key, certs, err := generateKeyCertPair()
	if err != nil {
		t.Fatalf("generateKeyCertPair() error = %v", err)
	}
	s, err := NewSigner(key, certs)
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
	basicVerification(sig, certs[len(certs)-1], t)
}

func TestSignWithoutExpiry(t *testing.T) {
	// sign with key
	key, certs, err := generateKeyCertPair()
	if err != nil {
		t.Fatalf("generateKeyCertPair() error = %v", err)
	}
	s, err := NewSigner(key, certs)
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
	basicVerification(sig, certs[len(certs)-1], t)
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
	sOpts := notation.SignOptions{
		Expiry: time.Now().UTC().Add(time.Hour),
	}
	if tsa != nil {
		sOpts.TSA = tsa
		tsaRoots := x509.NewCertPool()
		tsaRoots.AddCert(tsa.Certificate())
		sOpts.TSAVerifyOptions.Roots = tsaRoots
	}
	return desc, sOpts
}

func generateKeyCertPair() (crypto.PrivateKey, []*x509.Certificate, error) {
	rsaRoot := testhelper.GetRSARootCertificate()
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	certTuple := testhelper.GetRSACertTupleWithPK(pk, "tempCert", &rsaRoot)
	return pk, []*x509.Certificate{certTuple.Cert, rsaRoot.Cert}, nil
}

func basicVerification(sig []byte, trust *x509.Certificate, t *testing.T) {
	// basic verification
	sigEnv, err := signer.NewSignatureEnvelopeFromBytes(sig, signer.MediaTypeJWSJson)
	if err != nil {
		t.Fatalf("verification failed. error = %v", err)
	}

	sigInfo, vErr := sigEnv.Verify()
	if vErr != nil {
		t.Fatalf("verification failed. error = %v", err)
	}

	trustedCert, err := signer.VerifyAuthenticity(sigInfo, []*x509.Certificate{trust})

	if err !=nil || !trustedCert.Equal(trust) {
		t.Fatalf("VerifyAuthenticity failed. error = %v", err)
	}
}

func validateSignWithCerts(t *testing.T, key crypto.PrivateKey, certs []*x509.Certificate) {
	s, err := NewSigner(key, certs)
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
	basicVerification(sig, certs[len(certs)-1], t)
}
