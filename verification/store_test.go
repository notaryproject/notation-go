package verification

import (
	"fmt"
	"path/filepath"
	"runtime"
	"testing"
)

// TestLoadTrustStore tests a valid trust store
func TestLoadValidTrustStore(t *testing.T) {
	trustStore, err := LoadX509TrustStore(filepath.FromSlash("testdata/trust-store/ca/valid-trust-store"))
	if err != nil {
		t.Fatalf("could not load a valid trust store. %q", err)
	}
	if len(trustStore.Certificates) != 3 {
		t.Fatalf("valid trust store should have 3 certificates in it")
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
	path := filepath.FromSlash("testdata/trust-store/valid-trust-store_SYMLINK")
	_, err := LoadX509TrustStore(path)

	if err == nil || err.Error() != fmt.Sprintf("%q is not a regular directory (symlinks are not supported)", path) {
		t.Fatalf("symlink directories should return error : %q", err)
	}
}

func TestLoadTrustStoreWithSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping the symlink test on Windows")
	}
	path := filepath.FromSlash("testdata/trust-store/trust-store-with-cert-symlinks")
	failurePath := filepath.FromSlash("testdata/trust-store/trust-store-with-cert-symlinks/GlobalSignRootCA_SYMLINK.crt")
	_, err := LoadX509TrustStore(path)
	if err == nil || err.Error() != fmt.Sprintf("%q is not a regular file (directories or symlinks are not supported)", failurePath) {
		t.Fatalf("symlink certificates should return error : %q", err)
	}
}

func TestLoadTrustStoreWithDirs(t *testing.T) {
	path := filepath.FromSlash("testdata/trust-store/trust-store-with-directories")
	failurePath := filepath.FromSlash("testdata/trust-store/trust-store-with-directories/sub-dir")
	_, err := LoadX509TrustStore(path)
	if err == nil || err.Error() != fmt.Sprintf("%q is not a regular file (directories or symlinks are not supported)", failurePath) {
		t.Fatalf("sub directories should return error : %q", err)
	}
}

func TestLoadTrustStoreWithInvalidCerts(t *testing.T) {
	path := filepath.FromSlash("testdata/trust-store/trust-store-with-invalid-certs")
	failurePath := filepath.FromSlash("testdata/trust-store/trust-store-with-invalid-certs/invalid")
	_, err := LoadX509TrustStore(path)
	if err == nil || err.Error() != fmt.Sprintf("Error while reading certificates from %q. Error : \"x509: malformed certificate\"", failurePath) {
		t.Fatalf("invalid certs should return error : %q", err)
	}
}

func TestLoadTrustStoreWithLeafCerts(t *testing.T) {
	path := filepath.FromSlash("testdata/trust-store/trust-store-with-leaf-certs")
	failurePath := filepath.FromSlash("testdata/trust-store/trust-store-with-leaf-certs/non-ca.crt")
	_, err := LoadX509TrustStore(path)
	if err == nil || err.Error() != fmt.Sprintf("certificate with subject \"CN=lol,OU=lol,O=lol,L=lol,ST=Some-State,C=AU,1.2.840.113549.1.9.1=#13036c6f6c\" from file %q is not a CA certificate, only CA certificates (BasicConstraint CA=True) are allowed", failurePath) {
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
