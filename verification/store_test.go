package verification

import (
	"testing"
)

// TestLoadTrustStore tests a valid trust store
func TestLoadValidTrustStore(t *testing.T) {
	trustStore, err := LoadX509TrustStore("testdata/trust-store/valid-trust-store")
	if err != nil {
		t.Fatalf("could not load a valid trust store. %q", err)
	}
	if len(trustStore.Certificates) != 2 {
		t.Fatalf("valid trust store should have two certificates in it")
	}
}

func TestLoadSymlinkTrustStore(t *testing.T) {
	_, err := LoadX509TrustStore("testdata/trust-store/valid-trust-store_SYMLINK")
	if err == nil || err.Error() != "\"testdata/trust-store/valid-trust-store_SYMLINK\" is not a regular directory (symlinks are not supported)" {
		t.Fatalf("symlinks should return error : %q", err)
	}
}

func TestLoadTrustStoreWithSymlinks(t *testing.T) {
	_, err := LoadX509TrustStore("testdata/trust-store/trust-store-with-cert-symlinks")
	if err == nil || err.Error() != "\"testdata/trust-store/trust-store-with-cert-symlinks/GlobalSignRootCA_SYMLINK.crt\" is not a regular file (directories or symlinks are not supported)" {
		t.Fatalf("symlinks should return error : %q", err)
	}
}

func TestLoadTrustStoreWithDirs(t *testing.T) {
	_, err := LoadX509TrustStore("testdata/trust-store/trust-store-with-directories")
	if err == nil || err.Error() != "\"testdata/trust-store/trust-store-with-directories/sub-dir\" is not a regular file (directories or symlinks are not supported)" {
		t.Fatalf("sub directories should return error : %q", err)
	}
}

func TestLoadTrustStoreWithInvalidCerts(t *testing.T) {
	_, err := LoadX509TrustStore("testdata/trust-store/trust-store-with-invalid-certs")
	if err == nil || err.Error() != "Error while reading certificates from \"testdata/trust-store/trust-store-with-invalid-certs/invalid\". Error : \"x509: malformed certificate\"" {
		t.Fatalf("invalid certs should return error : %q", err)
	}
}

func TestLoadTrustStoreWithLeafCerts(t *testing.T) {
	_, err := LoadX509TrustStore("testdata/trust-store/trust-store-with-leaf-certs")
	if err == nil || err.Error() != "certificate with subject \"CN=lol,OU=lol,O=lol,L=lol,ST=Some-State,C=AU,1.2.840.113549.1.9.1=#13036c6f6c\" from file \"testdata/trust-store/trust-store-with-leaf-certs/non-ca.crt\" is not a CA certificate, only CA certificates (BasicConstraint CA=True) are allowed" {
		t.Fatalf("leaf cert in a trust store should return error : %q", err)
	}
}
