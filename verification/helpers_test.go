package verification

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"strconv"
	"testing"
)

func TestGetArtifactDigestFromUri(t *testing.T) {

	tests := []struct {
		artifactUri string
		digest      string
		wantErr     bool
	}{
		{"domain.com:80/repository:digest", "digest", false},
		{"domain.com/repository@sha256:digest", "digest", false},
		{"domain.com/repository", "", true},
		{"domain.com/repository@sha256", "", true},
		{"domain.com/repository@sha256:", "", true},
		{"", "", true},
		{"domain.com", "", true},
	}
	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			digest, err := getArtifactDigestFromUri(tt.artifactUri)

			if tt.wantErr != (err != nil) {
				t.Fatalf("TestGetArtifactDigestFromUri Error: %q WantErr: %v Input: %q", err, tt.wantErr, tt.artifactUri)
			} else if digest != tt.digest {
				t.Fatalf("TestGetArtifactDigestFromUri Want: %q Got: %v", tt.digest, digest)
			}
		})
	}
}

func TestLoadPolicyDocument(t *testing.T) {
	// non-existing policy file
	_, err := loadPolicyDocument(filepath.FromSlash("/non/existent"))
	if err == nil {
		t.Fatalf("TestLoadPolicyDocument should throw error for non existent policy")
	}
	// existing invalid json file
	path := filepath.Join(t.TempDir(), "invalid.json")
	err = ioutil.WriteFile(path, []byte(`{"invalid`), 0644)
	_, err = loadPolicyDocument(path)
	if err == nil {
		t.Fatalf("TestLoadPolicyDocument should throw error for invalid policy file. Error: %v", err)
	}

	// existing policy file
	path = filepath.Join(t.TempDir(), "trustpolicy.json")
	policyDoc1 := dummyPolicyDocument()
	policyJson, _ := json.Marshal(policyDoc1)
	err = ioutil.WriteFile(path, policyJson, 0644)
	_, err = loadPolicyDocument(path)
	if err != nil {
		t.Fatalf("TestLoadPolicyDocument should not throw error for an existing policy file. Error: %v", err)
	}
}

func TestLoadX509TrustStore(t *testing.T) {
	// load "ca" and "signingAuthority" trust store
	caStore := "ca:valid-trust-store"
	signingAuthorityStore := "signingAuthority:valid-trust-store"
	policyDoc1 := dummyPolicyDocument()
	policyDoc1.TrustPolicies[0].TrustStores = []string{caStore, signingAuthorityStore}
	trustStores, err := loadX509TrustStores(&policyDoc1, filepath.FromSlash("testdata/trust-store/"))
	if err != nil {
		t.Fatalf("TestLoadX509TrustStore should not throw error for a valid trust store. Error: %v", err)
	}
	if (len(trustStores)) != 2 {
		t.Fatalf("TestLoadX509TrustStore must load two trust stores")
	}
	if trustStores[caStore] == nil || trustStores[signingAuthorityStore] == nil {
		t.Fatalf("TestLoadX509TrustStore must load trust store associated with \"ca\" and \"signingAuthority\"")
	}
}
