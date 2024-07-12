// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package signer

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
	"regexp"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	_ "github.com/notaryproject/notation-core-go/signature/cose"
	_ "github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-core-go/testhelper"
	nx509 "github.com/notaryproject/notation-core-go/x509"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/internal/envelope"
	"github.com/notaryproject/notation-go/plugin/proto"
	"github.com/notaryproject/tspclient-go"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const rfc3161URL = "http://timestamp.digicert.com"

type keyCertPair struct {
	keySpecName string
	key         crypto.PrivateKey
	certs       []*x509.Certificate
}

var keyCertPairCollections []*keyCertPair

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
		ks, err := proto.EncodeKeySpec(keySpec)
		if err != nil {
			panic(fmt.Sprintf("setUpKeyCertPairCollections() failed, invalid keySpec: %v", err))
		}

		keyCertPairs = append(keyCertPairs, &keyCertPair{
			keySpecName: string(ks),
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
		ks, err := proto.EncodeKeySpec(keySpec)
		if err != nil {
			panic(fmt.Sprintf("setUpKeyCertPairCollections() failed, invalid keySpec: %v", err))
		}
		keyCertPairs = append(keyCertPairs, &keyCertPair{
			keySpecName: string(ks),
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

func prepareTestKeyCertFile(keyCert *keyCertPair, dir string) (string, string, error) {
	keyPath, certPath := filepath.Join(dir, keyCert.keySpecName+".key"), filepath.Join(dir, keyCert.keySpecName+".cert")
	keyBytes, err := generateKeyBytes(keyCert.key)
	if err != nil {
		return "", "", err
	}
	var certBytes []byte
	for _, cert := range keyCert.certs {
		certBytes = append(certBytes, generateCertPem(cert)...)
	}

	if err := os.WriteFile(keyPath, keyBytes, 0600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(certPath, certBytes, 0600); err != nil {
		return "", "", err
	}
	return keyPath, certPath, nil
}

func testSignerFromFile(t *testing.T, keyCert *keyCertPair, envelopeType, dir string) {
	keyPath, certPath, err := prepareTestKeyCertFile(keyCert, dir)
	if err != nil {
		t.Fatalf("prepareTestKeyCertFile() failed: %v", err)
	}
	s, err := NewFromFiles(keyPath, certPath)
	if err != nil {
		t.Fatalf("NewSignerFromFiles() failed: %v", err)
	}
	desc, opts := generateSigningContent()
	opts.SignatureMediaType = envelopeType
	sig, _, err := s.Sign(context.Background(), desc, opts)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}
	// basic verification
	basicVerification(t, sig, envelopeType, keyCert.certs[len(keyCert.certs)-1], nil)
}

func TestNewFromFiles(t *testing.T) {
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

func TestNewFromFilesError(t *testing.T) {
	tests := map[string]struct {
		keyPath  string
		certPath string
		errMsg   string
	}{
		"empty key path": {
			keyPath:  "",
			certPath: "someCert",
			errMsg:   "key path not specified",
		},
		"empty cert path": {
			keyPath:  "someKeyId",
			certPath: "",
			errMsg:   "certificate path not specified",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := NewFromFiles(tc.keyPath, tc.certPath)
			if err == nil || err.Error() != tc.errMsg {
				t.Fatalf("TestNewFromPluginFailed expects error %q, got %q", tc.errMsg, err.Error())
			}
		})
	}
}

func TestNewError(t *testing.T) {
	wantErr := "\"certs\" param is invalid. Error: empty certs"
	_, err := New(nil, nil)
	if err == nil || err.Error() != wantErr {
		t.Fatalf("TestNewFromPluginFailed expects error %q, got %q", wantErr, err.Error())
	}
}

func TestSignWithCertChain(t *testing.T) {
	// sign with key
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		for _, keyCert := range keyCertPairCollections {
			t.Run(fmt.Sprintf("envelopeType=%v_keySpec=%v", envelopeType, keyCert.keySpecName), func(t *testing.T) {
				validateSignWithCerts(t, envelopeType, keyCert.key, keyCert.certs, false)
			})
		}
	}
}

func TestSignWithTimestamping(t *testing.T) {
	// sign with key
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		for _, keyCert := range keyCertPairCollections {
			t.Run(fmt.Sprintf("envelopeType=%v_keySpec=%v", envelopeType, keyCert.keySpecName), func(t *testing.T) {
				validateSignWithCerts(t, envelopeType, keyCert.key, keyCert.certs, true)
			})
		}
	}

	// timestamping without timestamper
	envelopeType := signature.RegisteredEnvelopeTypes()[0]
	keyCert := keyCertPairCollections[0]
	s, err := New(keyCert.key, keyCert.certs)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	ctx := context.Background()
	desc, sOpts := generateSigningContent()
	sOpts.SignatureMediaType = envelopeType
	sOpts.TSARootCAs = x509.NewCertPool()
	_, _, err = s.Sign(ctx, desc, sOpts)
	expectedErrMsg := "timestamping: got TSARootCAs but nil Timestamper"
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected %s, but got %s", expectedErrMsg, err)
	}

	// timestamping without TSARootCAs
	desc, sOpts = generateSigningContent()
	sOpts.SignatureMediaType = envelopeType
	sOpts.Timestamper, err = tspclient.NewHTTPTimestamper(nil, rfc3161URL)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = s.Sign(ctx, desc, sOpts)
	expectedErrMsg = "timestamping: got Timestamper but nil TSARootCAs"
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected %s, but got %s", expectedErrMsg, err)
	}
}

func TestSignBlobWithCertChain(t *testing.T) {
	// sign with key
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		for _, keyCert := range keyCertPairCollections {
			t.Run(fmt.Sprintf("envelopeType=%v_keySpec=%v", envelopeType, keyCert.keySpecName), func(t *testing.T) {
				s, err := NewGenericSigner(keyCert.key, keyCert.certs)
				if err != nil {
					t.Fatalf("NewSigner() error = %v", err)
				}

				sOpts := notation.SignerSignOptions{
					SignatureMediaType: envelopeType,
				}
				sig, _, err := s.SignBlob(context.Background(), getDescriptorFunc(false), sOpts)
				if err != nil {
					t.Fatalf("Sign() error = %v", err)
				}

				// basic verification
				basicVerification(t, sig, envelopeType, keyCert.certs[len(keyCert.certs)-1], nil)
			})
		}
	}
}

func TestSignWithoutExpiry(t *testing.T) {
	// sign with key
	for _, envelopeType := range signature.RegisteredEnvelopeTypes() {
		for _, keyCert := range keyCertPairCollections {
			t.Run(fmt.Sprintf("envelopeType=%v_keySpec=%v", envelopeType, keyCert.keySpecName), func(t *testing.T) {
				s, err := New(keyCert.key, keyCert.certs)
				if err != nil {
					t.Fatalf("NewSigner() error = %v", err)
				}

				ctx := context.Background()
				desc, sOpts := generateSigningContent()
				sOpts.ExpiryDuration = 0 // reset expiry
				sOpts.SignatureMediaType = envelopeType
				sig, _, err := s.Sign(ctx, desc, sOpts)
				if err != nil {
					t.Fatalf("Sign() error = %v", err)
				}

				// basic verification
				basicVerification(t, sig, envelopeType, keyCert.certs[len(keyCert.certs)-1], nil)
			})
		}
	}
}

func signRSA(digest []byte, hash crypto.Hash, pk *rsa.PrivateKey) ([]byte, error) {
	return rsa.SignPSS(rand.Reader, pk, hash, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
}

func signECDSA(digest []byte, pk *ecdsa.PrivateKey) ([]byte, error) {
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
		return signECDSA(digest, key)
	default:
		return nil, errors.New("signing private key not supported")
	}
}

// generateSigningContent generates common signing content with options for testing.
func generateSigningContent() (ocispec.Descriptor, notation.SignerSignOptions) {
	content := "hello world"
	desc := ocispec.Descriptor{
		MediaType: "test media type",
		Digest:    digest.Canonical.FromString(content),
		Size:      int64(len(content)),
		Annotations: map[string]string{
			"identity": "test.registry.io/test:example",
			"foo":      "bar",
		},
	}
	sOpts := notation.SignerSignOptions{ExpiryDuration: 24 * time.Hour}

	return desc, sOpts
}

func basicVerification(t *testing.T, sig []byte, envelopeType string, trust *x509.Certificate, metadata *proto.GetMetadataResponse) {
	// basic verification
	sigEnv, err := signature.ParseEnvelope(envelopeType, sig)
	if err != nil {
		t.Fatalf("verification failed. error = %v", err)
	}

	envContent, vErr := sigEnv.Verify()
	if vErr != nil {
		t.Fatalf("verification failed. error = %v", err)
	}
	if err := envelope.ValidatePayloadContentType(&envContent.Payload); err != nil {
		t.Fatalf("verification failed. error = %v", err)
	}

	trustedCert, err := signature.VerifyAuthenticity(&envContent.SignerInfo, []*x509.Certificate{trust})

	if err != nil || !trustedCert.Equal(trust) {
		t.Fatalf("VerifyAuthenticity failed. error = %v", err)
	}

	verifySigningAgent(t, envContent.SignerInfo.UnsignedAttributes.SigningAgent, metadata)
}

func verifySigningAgent(t *testing.T, signingAgentId string, metadata *proto.GetMetadataResponse) {
	signingAgentRegex := regexp.MustCompile("^(?P<agent>.*) (?P<name>.*)/(?P<version>.*)$")
	match := signingAgentRegex.FindStringSubmatch(signingAgentId)

	results := map[string]string{}
	for i, name := range match {
		results[signingAgentRegex.SubexpNames()[i]] = name
	}

	if metadata == nil {
		if signingAgentId != signingAgent {
			t.Fatalf("Expected signingAgent of %s but signature contained %s instead", signingAgent, signingAgentId)
		}
	} else if results["agent"] != signingAgent || results["name"] != metadata.Name || results["version"] != metadata.Version {
		t.Fatalf("Expected signingAgent of %s %s/%s but signature contained %s instead", signingAgent, metadata.Name, metadata.Version, signingAgentId)
	}
}

func validateSignWithCerts(t *testing.T, envelopeType string, key crypto.PrivateKey, certs []*x509.Certificate, timestamp bool) {
	s, err := New(key, certs)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	ctx := context.Background()
	desc, sOpts := generateSigningContent()
	sOpts.SignatureMediaType = envelopeType
	if timestamp {
		sOpts.Timestamper, err = tspclient.NewHTTPTimestamper(nil, rfc3161URL)
		if err != nil {
			t.Fatal(err)
		}
		rootCerts, err := nx509.ReadCertificateFile("./testdata/DigiCertTSARootSHA384.cer")
		if err != nil {
			t.Fatal(err)
		}
		rootCAs := x509.NewCertPool()
		rootCAs.AddCert(rootCerts[0])
		sOpts.TSARootCAs = rootCAs
	}
	sig, _, err := s.Sign(ctx, desc, sOpts)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// basic verification
	basicVerification(t, sig, envelopeType, certs[len(certs)-1], nil)
}
