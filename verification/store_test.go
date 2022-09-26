package verification

import (
	"fmt"
	"path/filepath"
	"runtime"
	"testing"
)

// TestLoadTrustStore tests a valid trust store
func TestLoadValidTrustStore(t *testing.T) {
	trustStore, err := LoadX509TrustStore(filepath.FromSlash("testdata/truststore/x509/ca/valid-trust-store"))
	if err != nil {
		t.Fatalf("could not load a valid trust store. %q", err)
	}
	if len(trustStore.Certificates) != 3 {
		t.Fatalf("unexpected number of certificates in the trust store, expected: %d, got: %d", 3, len(trustStore.Certificates))
	}
	if trustStore.Prefix != "ca" {
		t.Fatalf("trust store prefix should be \"ca\"")
	}
}

func TestLoadSymlinkTrustStore(t *testing.T) {
	// TODO run symlink tests on Windows. See https://github.com/notaryproject/notation-go/issues/59
	if runtime.GOOS == "windows" {
		t.Skip("skipping the symlink test on Windows")
	}
	path := filepath.FromSlash("testdata/truststore/x509/valid-trust-store_SYMLINK")
	_, err := LoadX509TrustStore(path)

	if err == nil || err.Error() != fmt.Sprintf("%q is not a regular directory (symlinks are not supported)", path) {
		t.Fatalf("symlink directories should return error : %q", err)
	}
}

func TestLoadTrustStoreWithSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping the symlink test on Windows")
	}
	path := filepath.FromSlash("testdata/truststore/x509/trust-store-with-cert-symlinks")
	failurePath := filepath.FromSlash("testdata/truststore/x509/trust-store-with-cert-symlinks/GlobalSignRootCA_SYMLINK.crt")
	_, err := LoadX509TrustStore(path)
	if err == nil || err.Error() != fmt.Sprintf("%q is not a regular file (directories or symlinks are not supported)", failurePath) {
		t.Fatalf("symlink certificates should return error : %q", err)
	}
}

func TestLoadTrustStoreWithDirs(t *testing.T) {
	path := filepath.FromSlash("testdata/truststore/x509/trust-store-with-directories")
	failurePath := filepath.FromSlash("testdata/truststore/x509/trust-store-with-directories/sub-dir")
	_, err := LoadX509TrustStore(path)
	if err == nil || err.Error() != fmt.Sprintf("%q is not a regular file (directories or symlinks are not supported)", failurePath) {
		t.Fatalf("sub directories should return error : %q", err)
	}
}

func TestLoadTrustStoreWithInvalidCerts(t *testing.T) {
	path := filepath.FromSlash("testdata/truststore/x509/trust-store-with-invalid-certs")
	failurePath := filepath.FromSlash("testdata/truststore/x509/trust-store-with-invalid-certs/invalid")
	_, err := LoadX509TrustStore(path)
	if err == nil || err.Error() != fmt.Sprintf("error while reading certificates from %q: x509: malformed certificate", failurePath) {
		t.Fatalf("invalid certs should return error : %q", err)
	}
}

func TestLoadTrustStoreWithLeafCerts(t *testing.T) {
	path := filepath.FromSlash("testdata/truststore/x509/trust-store-with-leaf-certs")
	failurePath := filepath.FromSlash("testdata/truststore/x509/trust-store-with-leaf-certs/non-ca.crt")
	_, err := LoadX509TrustStore(path)
	if err == nil || err.Error() != fmt.Sprintf("certificate with subject \"CN=wabbit-networks.io,O=Notary,L=Seattle,ST=WA,C=US\" from file %q is not a CA certificate or self-signed signing certificate", failurePath) {
		t.Fatalf("leaf cert in a trust store should return error : %q", err)
	}
}

func TestLoadTrustStoreWithLeafCertsInSingleFile(t *testing.T) {
	path := filepath.FromSlash("testdata/truststore/x509/trust-store-with-leaf-certs-in-single-file")
	failurePath := filepath.FromSlash("testdata/truststore/x509/trust-store-with-leaf-certs-in-single-file/RootAndLeafCerts.crt")
	_, err := LoadX509TrustStore(path)
	if err == nil || err.Error() != fmt.Sprintf("certificate with subject \"CN=wabbit-networks.io,O=Notary,L=Seattle,ST=WA,C=US\" from file %q is not a CA certificate or self-signed signing certificate", failurePath) {
		t.Fatalf("leaf cert in a trust store should return error : %q", err)
	}
}

func TestLoadTrustStoreWithEmptyDir(t *testing.T) {
	path := t.TempDir()
	_, err := LoadX509TrustStore(path)
	if err == nil || err.Error() != fmt.Sprintf("trust store %q has no x509 certificates", path) {
		t.Fatalf("empty trust store should throw an error : %q", err)
	}
}
