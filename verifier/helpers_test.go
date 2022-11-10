package verifier

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
)

func dummyPolicyStatement() (policyStatement trustpolicy.TrustPolicy) {
	policyStatement = trustpolicy.TrustPolicy{
		Name:                  "test-statement-name",
		RegistryScopes:        []string{"registry.acme-rockets.io/software/net-monitor"},
		SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: "strict"},
		TrustStores:           []string{"ca:valid-trust-store", "signingAuthority:valid-trust-store"},
		TrustedIdentities:     []string{"x509.subject:CN=Notation Test Root,O=Notary,L=Seattle,ST=WA,C=US"},
	}
	return
}

func dummyPolicyDocument() (policyDoc trustpolicy.Document) {
	policyDoc = trustpolicy.Document{
		Version:       "1.0",
		TrustPolicies: []trustpolicy.TrustPolicy{dummyPolicyStatement()},
	}
	return
}

func TestGetArtifactDigestFromUri(t *testing.T) {

	tests := []struct {
		artifactReference string
		digest            string
		wantErr           bool
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
			digest, err := getArtifactDigestFromReference(tt.artifactReference)

			if tt.wantErr != (err != nil) {
				t.Fatalf("TestGetArtifactDigestFromUri Error: %q WantErr: %v Input: %q", err, tt.wantErr, tt.artifactReference)
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
	dir.UserConfigDir = "testdata"
	caCerts, err := loadX509TrustStores(context.Background(), signature.SigningSchemeX509, &dummyPolicy)
	if err != nil {
		t.Fatalf("TestLoadX509TrustStore should not throw error for a valid trust store. Error: %v", err)
	}
	saCerts, err := loadX509TrustStores(context.Background(), signature.SigningSchemeX509SigningAuthority, &dummyPolicy)
	if err != nil {
		t.Fatalf("TestLoadX509TrustStore should not throw error for a valid trust store. Error: %v", err)
	}
	if len(caCerts) != 3 || len(saCerts) != 3 {
		t.Fatalf("Both of the named stores should have 3 certs")
	}
}

func getArtifactDigestFromReference(artifactReference string) (string, error) {
	invalidUriErr := fmt.Errorf("artifact URI %q could not be parsed, make sure it is the fully qualified OCI artifact URI without the scheme/protocol. e.g domain.com:80/my/repository@sha256:digest", artifactReference)
	i := strings.LastIndex(artifactReference, "@")
	if i < 0 || i+1 == len(artifactReference) {
		return "", invalidUriErr
	}

	j := strings.LastIndex(artifactReference[i+1:], ":")
	if j < 0 || j+1 == len(artifactReference[i+1:]) {
		return "", invalidUriErr
	}

	return artifactReference[i+1:], nil
}
