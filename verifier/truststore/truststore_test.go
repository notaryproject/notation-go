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

package truststore

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	corex509 "github.com/notaryproject/notation-core-go/x509"
	"github.com/notaryproject/notation-go/dir"
)

var trustStore = NewX509TrustStore(dir.NewSysFS(filepath.FromSlash("../testdata/")))

// TestLoadTrustStore tests a valid trust store
func TestLoadValidTrustStore(t *testing.T) {
	_, err := trustStore.GetCertificates(context.Background(), "ca", "valid-trust-store")
	if err != nil {
		t.Fatalf("could not get certificates from trust store. %q", err)
	}
}

// TestLoadValidTrustStoreWithSelfSignedSigningCertificate tests a valid trust store with self-signed signing certificate
func TestLoadValidTrustStoreWithSelfSignedSigningCertificate(t *testing.T) {
	certs, err := trustStore.GetCertificates(context.Background(), "ca", "valid-trust-store-self-signed")
	if err != nil {
		t.Fatalf("could not get certificates from trust store. %q", err)
	}
	if len(certs) != 1 {
		t.Fatalf("unexpected number of certificates in the trust store, expected: %d, got: %d", 1, len(certs))
	}
}

func TestLoadTrustStoreWithInvalidCerts(t *testing.T) {
	// testing ../testdata/truststore/x509/ca/trust-store-with-invalid-certs/invalid
	expectedErr := fmt.Errorf("failed to read the trusted certificate %s in trust store %s of type %s", "invalid", "trust-store-with-invalid-certs", "ca")
	_, err := trustStore.GetCertificates(context.Background(), "ca", "trust-store-with-invalid-certs")
	if err == nil || err.Error() != expectedErr.Error() {
		t.Fatalf("invalid certs should return error: %q", expectedErr)
	}
}

func TestLoadTrustStoreWithLeafCerts(t *testing.T) {
	// testing ../testdata/truststore/x509/ca/trust-store-with-leaf-certs/non-ca.crt
	expectedErrMsg := fmt.Sprintf("failed to validate the trusted certificate %s in trust store %s of type %s", "non-ca.crt", "trust-store-with-leaf-certs", "ca")
	_, err := trustStore.GetCertificates(context.Background(), "ca", "trust-store-with-leaf-certs")
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("leaf cert in a trust store should return error: %s, got: %v", expectedErrMsg, err)
	}
}

func TestLoadTrustStoreWithLeafCertsInSingleFile(t *testing.T) {
	// testing ../testdata/truststore/x509/ca/trust-store-with-leaf-certs-in-single-file/RootAndLeafCerts.crt
	expectedErrMsg := fmt.Sprintf("failed to validate the trusted certificate %s in trust store %s of type %s", "RootAndLeafCerts.crt", "trust-store-with-leaf-certs-in-single-file", "ca")
	_, err := trustStore.GetCertificates(context.Background(), "ca", "trust-store-with-leaf-certs-in-single-file")
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("leaf cert in a trust store should return error: %s, got: %v", expectedErrMsg, err)
	}
}

// TestValidCerts tests valid trust store cert
func TestValidateCerts(t *testing.T) {
	joinedPath := filepath.FromSlash("../testdata/truststore/x509/ca/valid-trust-store/GlobalSign.der")
	certs, err := corex509.ReadCertificateFile(joinedPath)
	if err != nil {
		t.Fatalf("failed to read the trusted certificate %q: %q", joinedPath, err)
	}
	err = ValidateCertificates(certs)
	if err != nil {
		t.Fatalf("expected to get nil err, got %v", err)
	}
}

// TestValidateCertsWithLeafCert tests invalid trust store leaf cert
func TestValidateCertsWithLeafCert(t *testing.T) {
	failurePath := filepath.FromSlash("../testdata/truststore/x509/ca/trust-store-with-leaf-certs/non-ca.crt")
	certs, err := corex509.ReadCertificateFile(failurePath)
	if err != nil {
		t.Fatalf("failed to read the trusted certificate %q: %q", failurePath, err)
	}
	expectedErr := errors.New("certificate with subject \"CN=wabbit-networks.io,O=Notary,L=Seattle,ST=WA,C=US\" is not a CA certificate or self-signed signing certificate")
	err = ValidateCertificates(certs)
	if err == nil || err.Error() != expectedErr.Error() {
		t.Fatalf("leaf cert in a trust store should return error %q, got: %v", expectedErr, err)
	}
}

func TestGetCertFromInvalidTsaTrustStore(t *testing.T) {
	t.Run("non CA certificate", func(t *testing.T) {
		// testing ../testdata/truststore/x509/tsa/test-nonCA/wabbit-networks.io
		expectedErrMsg := `trusted certificate wabbit-networks.io.crt in trust store test-nonCA of type tsa is invalid: certificate with subject "CN=wabbit-networks.io,O=Notary,L=Seattle,ST=WA,C=US" is not a root CA certificate: x509: invalid signature: parent certificate cannot sign this kind of certificate`
		_, err := trustStore.GetCertificates(context.Background(), "tsa", "test-nonCA")
		if err == nil || err.Error() != expectedErrMsg {
			t.Fatalf("expected error: %s, but got %s", expectedErrMsg, err)
		}
	})

	t.Run("not self-issued", func(t *testing.T) {
		//testing ../testdata/truststore/x509/tsa/test-nonSelfIssued/nonSelfIssued.crt
		expectedErrMsg := `trusted certificate nonSelfIssued.crt in trust store test-nonSelfIssued of type tsa is invalid: certificate with subject "CN=Notation Test Revokable RSA Chain Cert 2,O=Notary,L=Seattle,ST=WA,C=US" is not a root CA certificate: issuer (CN=Notation Test Revokable RSA Chain Cert Root,O=Notary,L=Seattle,ST=WA,C=US) and subject (CN=Notation Test Revokable RSA Chain Cert 2,O=Notary,L=Seattle,ST=WA,C=US) are not the same`
		_, err := trustStore.GetCertificates(context.Background(), "tsa", "test-nonSelfIssued")
		if err == nil || err.Error() != expectedErrMsg {
			t.Fatalf("expected error: %s, but got %s", expectedErrMsg, err)
		}
	})
}
