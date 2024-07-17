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

package verifier

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
)

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

func TestLoadX509TrustStore(t *testing.T) {
	// load "ca" and "signingAuthority" trust store
	caStore := "ca:valid-trust-store"
	signingAuthorityStore := "signingAuthority:valid-trust-store"
	dummyPolicy := dummyOCIPolicyDocument().TrustPolicies[0]
	dummyPolicy.TrustStores = []string{caStore, signingAuthorityStore}
	dir.UserConfigDir = "testdata"
	x509truststore := truststore.NewX509TrustStore(dir.ConfigFS())
	_, err := loadX509TrustStores(context.Background(), signature.SigningSchemeX509, dummyPolicy.Name, dummyPolicy.TrustStores, x509truststore)
	if err != nil {
		t.Fatalf("TestLoadX509TrustStore should not throw error for a valid trust store. Error: %v", err)
	}
	_, err = loadX509TrustStores(context.Background(), signature.SigningSchemeX509SigningAuthority, dummyPolicy.Name, dummyPolicy.TrustStores, x509truststore)
	if err != nil {
		t.Fatalf("TestLoadX509TrustStore should not throw error for a valid trust store. Error: %v", err)
	}
}

func TestIsCriticalFailure(t *testing.T) {
	var dummyError = errors.New("critical failure")
	tests := []struct {
		result          notation.ValidationResult
		criticalFailure bool
	}{
		{notation.ValidationResult{Action: trustpolicy.ActionEnforce, Error: dummyError}, true},
		{notation.ValidationResult{Action: trustpolicy.ActionLog, Error: dummyError}, false},
		{notation.ValidationResult{Action: trustpolicy.ActionSkip, Error: dummyError}, false},
	}
	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			endResult := isCriticalFailure(&tt.result)

			if endResult != tt.criticalFailure {
				t.Fatalf("TestIsCriticalFailure Expected: %v Got: %v", tt.criticalFailure, endResult)
			}
		})
	}
}

func TestLoadX509TSATrustStores(t *testing.T) {
	policyDoc := trustpolicy.Document{
		Version: "1.0",
		TrustPolicies: []trustpolicy.TrustPolicy{
			{
				Name:                  "testTSA",
				RegistryScopes:        []string{"*"},
				SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: "strict"},
				TrustStores:           []string{"tsa:test-timestamp"},
				TrustedIdentities:     []string{"*"},
			},
		},
	}
	dir.UserConfigDir = "testdata"
	x509truststore := truststore.NewX509TrustStore(dir.ConfigFS())
	policyStatement := policyDoc.TrustPolicies[0]
	_, err := loadX509TSATrustStores(context.Background(), signature.SigningSchemeX509, policyStatement.Name, policyStatement.TrustStores, x509truststore)
	if err != nil {
		t.Fatalf("TestLoadX509TrustStore should not throw error for a valid trust store. Error: %v", err)
	}

	_, err = loadX509TSATrustStores(context.Background(), signature.SigningSchemeX509SigningAuthority, policyStatement.Name, policyStatement.TrustStores, x509truststore)
	expectedErrMsg := "error while loading the TSA trust store, signing scheme must be notary.x509, but got notary.x509.signingAuthority"
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected %s, but got %s", expectedErrMsg, err)
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

func dummyOCIPolicyDocument() (policyDoc trustpolicy.OCIDocument) {
	return trustpolicy.OCIDocument{
		Version: "1.0",
		TrustPolicies: []trustpolicy.OCITrustPolicy{
			{
				Name:                  "test-statement-name",
				RegistryScopes:        []string{"registry.acme-rockets.io/software/net-monitor"},
				SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: "strict"},
				TrustStores:           []string{"ca:valid-trust-store", "signingAuthority:valid-trust-store"},
				TrustedIdentities:     []string{"x509.subject:CN=Notation Test Root,O=Notary,L=Seattle,ST=WA,C=US"},
			},
		},
	}
}

func dummyBlobPolicyDocument() (policyDoc trustpolicy.BlobDocument) {
	return trustpolicy.BlobDocument{
		Version: "1.0",
		TrustPolicies: []trustpolicy.BlobTrustPolicy{
			{
				Name:                  "blob-test-statement-name",
				SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: "strict"},
				TrustStores:           []string{"ca:valid-trust-store", "signingAuthority:valid-trust-store"},
				TrustedIdentities:     []string{"x509.subject:CN=Notation Test Root,O=Notary,L=Seattle,ST=WA,C=US"},
			},
		},
	}
}
