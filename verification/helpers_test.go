package verification

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go/dir"
)

func TestGetArtifactDigestFromUri(t *testing.T) {

	tests := []struct {
		artifactUri string
		digest      string
		wantErr     bool
	}{
		{"domain.com/repository@sha256:digest", "sha256:digest", false},
		{"domain.com:80/repository:digest", "", true},
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
	tempRoot := t.TempDir()
	dir.UserConfigDir = tempRoot
	_, err := loadPolicyDocument()
	if err == nil {
		t.Fatalf("TestLoadPolicyDocument should throw error for non existent policy")
	}

	// existing invalid json file
	tempRoot = t.TempDir()
	dir.UserConfigDir = tempRoot
	path := filepath.Join(tempRoot, "invalid.json")
	err = os.WriteFile(path, []byte(`{"invalid`), 0644)
	if err != nil {
		t.Fatalf("TestLoadPolicyDocument create invalid policy file failed. Error: %v", err)
	}
	_, err = loadPolicyDocument()
	if err == nil {
		t.Fatalf("TestLoadPolicyDocument should throw error for invalid policy file. Error: %v", err)
	}

	// existing policy file
	tempRoot = t.TempDir()
	dir.UserConfigDir = tempRoot
	path = filepath.Join(tempRoot, "trustpolicy.json")
	policyDoc1 := dummyPolicyDocument()
	policyJson, _ := json.Marshal(policyDoc1)
	err = os.WriteFile(path, policyJson, 0644)
	if err != nil {
		t.Fatalf("TestLoadPolicyDocument create valid policy file failed. Error: %v", err)
	}
	_, err = loadPolicyDocument()
	if err != nil {
		t.Fatalf("TestLoadPolicyDocument should not throw error for an existing policy file. Error: %v", err)
	}
}

func TestLoadX509TrustStore(t *testing.T) {
	// load "ca" and "signingAuthority" trust store
	caStore := "ca:valid-trust-store"
	signingAuthorityStore := "signingAuthority:valid-trust-store"
	dummyPolicy := dummyPolicyStatement()
	dummyPolicy.TrustStores = []string{caStore, signingAuthorityStore}
	dir.UserConfigDir = "./testdata"
	caTrustStores, err := loadX509TrustStores(signature.SigningSchemeX509, &dummyPolicy)
	if err != nil {
		t.Fatalf("TestLoadX509TrustStore should not throw error for a valid trust store. Error: %v", err)
	}
	saTrustStores, err := loadX509TrustStores(signature.SigningSchemeX509SigningAuthority, &dummyPolicy)
	if err != nil {
		t.Fatalf("TestLoadX509TrustStore should not throw error for a valid trust store. Error: %v", err)
	}
	if len(caTrustStores) != 1 || len(saTrustStores) != 1 {
		t.Fatalf("TestLoadX509TrustStore must load one trust store of each 'ca' and 'signingAuthority' prefixes")
	}
}
