package truststore

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/notaryproject/notation-go/dir"
)

var trustStore = NewX509TrustStore(dir.NewSysFS(filepath.FromSlash("../testdata/")))

// TestLoadTrustStore tests a valid trust store
func TestLoadValidTrustStore(t *testing.T) {
	certs, err := trustStore.GetCertificates(context.Background(), "ca", "valid-trust-store")
	if err != nil {
		t.Fatalf("could not get certificates from trust store. %q", err)
	}
	if len(certs) != 4 {
		t.Fatalf("unexpected number of certificates in the trust store, expected: %d, got: %d", 4, len(certs))
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
	failurePath := filepath.FromSlash("../testdata/truststore/x509/ca/trust-store-with-invalid-certs/invalid")
	expectedErr := fmt.Errorf("error while reading certificates from %q: x509: malformed certificate", failurePath)
	_, err := trustStore.GetCertificates(context.Background(), "ca", "trust-store-with-invalid-certs")
	if err == nil || err.Error() != expectedErr.Error() {
		t.Fatalf("invalid certs should return error: %q", expectedErr)
	}
}

func TestLoadTrustStoreWithLeafCerts(t *testing.T) {
	failurePath := filepath.FromSlash("../testdata/truststore/x509/ca/trust-store-with-leaf-certs/non-ca.crt")
	expectedErr := fmt.Errorf("certificate with subject \"CN=wabbit-networks.io,O=Notary,L=Seattle,ST=WA,C=US\" from file %q is not a CA certificate or self-signed signing certificate", failurePath)
	_, err := trustStore.GetCertificates(context.Background(), "ca", "trust-store-with-leaf-certs")
	if err == nil || err.Error() != expectedErr.Error() {
		t.Fatalf("leaf cert in a trust store should return error: %q", expectedErr)
	}
}

func TestLoadTrustStoreWithLeafCertsInSingleFile(t *testing.T) {
	failurePath := filepath.FromSlash("../testdata/truststore/x509/ca/trust-store-with-leaf-certs-in-single-file/RootAndLeafCerts.crt")
	expectedErr := fmt.Errorf("certificate with subject \"CN=wabbit-networks.io,O=Notary,L=Seattle,ST=WA,C=US\" from file %q is not a CA certificate or self-signed signing certificate", failurePath)
	_, err := trustStore.GetCertificates(context.Background(), "ca", "trust-store-with-leaf-certs-in-single-file")
	if err == nil || err.Error() != expectedErr.Error() {
		t.Fatalf("leaf cert in a trust store should return error: %q", expectedErr)
	}
}
