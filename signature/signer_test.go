package signature

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/testhelper"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/crypto/timestamp/timestamptest"
	"github.com/opencontainers/go-digest"
)

var keyCertPairCollections []*keyCertPair

// setUpKeyCertPairCollections setups all combinations of private key and certificates
func setUpKeyCertPairCollections() {
	// rsa
	for _, k := range []int{2048, 3072, 4096} {
		rsaRoot := testhelper.GetRSARootCertificate()
		certTuple := testhelper.GetRSACertTuple(k)
		keyCertPairCollections = append(keyCertPairCollections, &keyCertPair{
			name:  "RSA_" + strconv.Itoa(k),
			key:   certTuple.PrivateKey,
			certs: []*x509.Certificate{certTuple.Cert, rsaRoot.Cert},
		})
	}

	// ecdsa
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		ecdsaRoot := testhelper.GetECRootCertificate()
		certTuple := testhelper.GetECCertTuple(curve)
		bitSize := certTuple.PrivateKey.Params().BitSize
		keyCertPairCollections = append(keyCertPairCollections, &keyCertPair{
			name:  "EC_" + strconv.Itoa(bitSize),
			key:   certTuple.PrivateKey,
			certs: []*x509.Certificate{certTuple.Cert, ecdsaRoot.Cert},
		})
	}
}

func init() {
	setUpKeyCertPairCollections()
}

func TestNewSignerFromFiles(t *testing.T) {
	t.Skip("Please implement TestNewSignerFromFiles test")
}

func TestSignWithCertChain(t *testing.T) {
	// sign with key
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		for _, keyCert := range keyCertPairCollections {
			t.Run(fmt.Sprintf("envelopeType:%v,keySpec:%v", envelopeType, keyCert.name), func(t *testing.T) {
				validateSignWithCerts(t, envelopeType, keyCert.key, keyCert.certs)
			})
		}
	}
}

// TODO: Enable once we have timestamping inplace https://github.com/notaryproject/notation-go/issues/78
func TestSignWithTimestamp(t *testing.T) {
	t.Skip("Skipping testing as we dont have timestamping hooked up")
	// prepare signer
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		for _, keyCert := range keyCertPairCollections {
			t.Run(fmt.Sprintf("envelopeType:%v,keySpec:%v", envelopeType, keyCert.name), func(t *testing.T) {
				s, err := NewSigner(keyCert.key, keyCert.certs, envelopeType)
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
				basicVerification(t, sig, envelopeType, keyCert.certs[len(keyCert.certs)-1])
			})
		}
	}
}

func TestSignWithoutExpiry(t *testing.T) {
	// sign with key
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		for _, keyCert := range keyCertPairCollections {
			t.Run(fmt.Sprintf("envelopeType:%v,keySpec:%v", envelopeType, keyCert.name), func(t *testing.T) {
				s, err := NewSigner(keyCert.key, keyCert.certs, envelopeType)
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
				basicVerification(t, sig, envelopeType, keyCert.certs[len(keyCert.certs)-1])
			})
		}
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

func basicVerification(t *testing.T, sig []byte, envelopeType string, trust *x509.Certificate) {
	// basic verification
	sigEnv, err := signature.ParseEnvelope(envelopeType, sig)
	if err != nil {
		t.Fatalf("verification failed. error = %v", err)
	}

	_, sigInfo, vErr := sigEnv.Verify()
	if vErr != nil {
		t.Fatalf("verification failed. error = %v", err)
	}

	trustedCert, err := signature.VerifyAuthenticity(sigInfo, []*x509.Certificate{trust})

	if err != nil || !trustedCert.Equal(trust) {
		t.Fatalf("VerifyAuthenticity failed. error = %v", err)
	}
}

func validateSignWithCerts(t *testing.T, envelopeType string, key crypto.PrivateKey, certs []*x509.Certificate) {
	s, err := NewSigner(key, certs, envelopeType)
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
	basicVerification(t, sig, envelopeType, certs[len(certs)-1])
}
