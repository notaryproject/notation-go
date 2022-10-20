package signature

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/testhelper"
	"github.com/notaryproject/notation-core-go/timestamp/timestamptest"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/plugin"
	"github.com/opencontainers/go-digest"
)

type keyCertPair struct {
	keySpecName string
	key         crypto.PrivateKey
	certs       []*x509.Certificate
}

var keyCertPairCollections []*keyCertPair

const testKeyID = "testKeyID"

// setUpKeyCertPairCollections setups all combinations of private key and certificates.
func setUpKeyCertPairCollections() []*keyCertPair {
	// rsa
	var keyCertPairs []*keyCertPair
	for _, k := range []int{2048, 3072, 4096} {
		rsaRoot := testhelper.GetRSARootCertificate()
		certTuple := testhelper.GetRSACertTuple(k)
		keySpec, err := signature.ExtractKeySpec(certTuple.Cert)
		if err != nil {
			panic(fmt.Sprintf("setUpKeyCertPairCollections() failed, invalid keySpec: %v", err))
		}
		keyCertPairs = append(keyCertPairs, &keyCertPair{
			keySpecName: plugin.KeySpecString(keySpec),
			key:         certTuple.PrivateKey,
			certs:       []*x509.Certificate{certTuple.Cert, rsaRoot.Cert},
		})
	}

	// ecdsa
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		ecdsaRoot := testhelper.GetECRootCertificate()
		certTuple := testhelper.GetECCertTuple(curve)
		keySpec, err := signature.ExtractKeySpec(certTuple.Cert)
		if err != nil {
			panic(fmt.Sprintf("setUpKeyCertPairCollections() failed, invalid keySpec: %v", err))
		}
		keyCertPairs = append(keyCertPairs, &keyCertPair{
			keySpecName: plugin.KeySpecString(keySpec),
			key:         certTuple.PrivateKey,
			certs:       []*x509.Certificate{certTuple.Cert, ecdsaRoot.Cert},
		})
	}
	return keyCertPairs
}

func init() {
	keyCertPairCollections = setUpKeyCertPairCollections()
}

func generateCertPem(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func generateKeyBytes(key crypto.PrivateKey) (keyBytes []byte, err error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		keyBytes, err = x509.MarshalPKCS8PrivateKey(k)
	case *ecdsa.PrivateKey:
		keyBytes, err = x509.MarshalECPrivateKey(k)
	default:
		return nil, errors.New("private key type not supported")
	}
	if err != nil {
		return nil, err
	}
	keyBytes = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	return keyBytes, nil
}

func prepareTestKeyCertFile(keyCert *keyCertPair, envelopeType, dir string) (string, string, error) {
	keyPath, certPath := filepath.Join(dir, keyCert.keySpecName+".key"), filepath.Join(dir, keyCert.keySpecName+".cert")
	keyBytes, err := generateKeyBytes(keyCert.key)
	if err != nil {
		return "", "", err
	}
	var certBytes []byte
	for _, cert := range keyCert.certs {
		certBytes = append(certBytes, generateCertPem(cert)...)
	}

	if err := os.WriteFile(keyPath, keyBytes, 0666); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(certPath, certBytes, 0666); err != nil {
		return "", "", err
	}
	return keyPath, certPath, nil
}

func testSignerFromFile(t *testing.T, keyCert *keyCertPair, envelopeType, dir string) {
	keyPath, certPath, err := prepareTestKeyCertFile(keyCert, envelopeType, dir)
	if err != nil {
		t.Fatalf("prepareTestKeyCertFile() failed: %v", err)
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
	// basic verification
	basicVerification(t, sig, envelopeType, keyCert.certs[len(keyCert.certs)-1])
}

func TestNewSignerFromFiles(t *testing.T) {
	// sign with key
	dir := t.TempDir()
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		for _, keyCert := range keyCertPairCollections {
			t.Run(fmt.Sprintf("envelopeType=%v_keySpec=%v", envelopeType, keyCert.keySpecName), func(t *testing.T) {
				testSignerFromFile(t, keyCert, envelopeType, dir)
			})
		}
	}
}

func TestSignWithCertChain(t *testing.T) {
	// sign with key
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		for _, keyCert := range keyCertPairCollections {
			t.Run(fmt.Sprintf("envelopeType=%v_keySpec=%v", envelopeType, keyCert.keySpecName), func(t *testing.T) {
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
			t.Run(fmt.Sprintf("envelopeType=%v_keySpec=%v", envelopeType, keyCert.keySpecName), func(t *testing.T) {
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
			t.Run(fmt.Sprintf("envelopeType=%v_keySpec=%v", envelopeType, keyCert.keySpecName), func(t *testing.T) {
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

func signRSA(digest []byte, hash crypto.Hash, pk *rsa.PrivateKey) ([]byte, error) {
	return rsa.SignPSS(rand.Reader, pk, hash, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
}

func signECDSA(digest []byte, hash crypto.Hash, pk *ecdsa.PrivateKey) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, pk, digest)
	if err != nil {
		return nil, err
	}
	n := (pk.Curve.Params().N.BitLen() + 7) / 8
	sig := make([]byte, 2*n)
	r.FillBytes(sig[:n])
	s.FillBytes(sig[n:])
	return sig, nil
}

func localSign(payload []byte, hash crypto.Hash, pk crypto.PrivateKey) ([]byte, error) {
	h := hash.New()
	h.Write(payload)
	digest := h.Sum(nil)
	switch key := pk.(type) {
	case *rsa.PrivateKey:
		return signRSA(digest, hash, key)
	case *ecdsa.PrivateKey:
		return signECDSA(digest, hash, key)
	default:
		return nil, errors.New("signing private key not supported")
	}
}

func TestExternalSigner_Sign(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		for _, keyCert := range keyCertPairCollections {
			externalRunner := newMockProvider(keyCert.key, keyCert.certs, testKeyID)
			s, err := NewSignerPlugin(externalRunner, testKeyID, nil, envelopeType)
			if err != nil {
				t.Fatalf("NewSigner() error = %v", err)
			}
			sig, err := s.Sign(context.Background(), validSignDescriptor, validSignOpts)
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}
			// basic verification
			basicVerification(t, sig, envelopeType, keyCert.certs[len(keyCert.certs)-1])
		}
	}
}

func TestExternalSigner_SignEnvelope(t *testing.T) {
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		for _, keyCert := range keyCertPairCollections {
			t.Run(fmt.Sprintf("envelopeType=%v_keySpec=%v", envelopeType, keyCert.keySpecName), func(t *testing.T) {
				externalRunner := newMockEnvelopeProvider(keyCert.key, keyCert.certs, testKeyID)
				p := newExternalProvider(externalRunner, testKeyID)
				s, err := NewSignerPlugin(p, testKeyID, nil, envelopeType)
				if err != nil {
					t.Fatalf("NewSigner() error = %v", err)
				}
				sig, err := s.Sign(context.Background(), validSignDescriptor, validSignOpts)
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

	envContent, vErr := sigEnv.Verify()
	if vErr != nil {
		t.Fatalf("verification failed. error = %v", err)
	}
	if err := ValidatePayloadContentType(&envContent.Payload); err != nil {
		t.Fatalf("verification failed. error = %v", err)
	}

	trustedCert, err := signature.VerifyAuthenticity(&envContent.SignerInfo, []*x509.Certificate{trust})

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
