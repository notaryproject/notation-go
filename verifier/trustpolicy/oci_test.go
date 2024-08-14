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

package trustpolicy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/notaryproject/notation-go/dir"
)

func TestLoadOCIDocumentFromOldFileLocation(t *testing.T) {
	tempRoot := t.TempDir()
	dir.UserConfigDir = tempRoot
	path := filepath.Join(tempRoot, "trustpolicy.json")
	policyJson, _ := json.Marshal(dummyOCIPolicyDocument())
	if err := os.WriteFile(path, policyJson, 0600); err != nil {
		t.Fatalf("TestLoadOCIDocument write policy file failed. Error: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tempRoot) })

	if _, err := LoadOCIDocument(); err != nil {
		t.Fatalf("LoadOCIDocument() should not throw error for an existing policy file. Error: %v", err)
	}
}

func TestLoadOCIDocumentFromNewFileLocation(t *testing.T) {
	tempRoot := t.TempDir()
	dir.UserConfigDir = tempRoot
	path := filepath.Join(tempRoot, "trustpolicy.json")
	policyJson, _ := json.Marshal(dummyOCIPolicyDocument())
	if err := os.WriteFile(path, policyJson, 0600); err != nil {
		t.Fatalf("TestLoadOCIDocument write policy file failed. Error: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tempRoot) })

	if _, err := LoadOCIDocument(); err != nil {
		t.Fatalf("LoadOCIDocument() should not throw error for an existing policy file. Error: %v", err)
	}
}

func TestLoadOCIDocumentError(t *testing.T) {
	tempRoot := t.TempDir()
	dir.UserConfigDir = tempRoot
	if _, err := LoadOCIDocument(); err == nil {
		t.Fatalf("LoadOCIDocument() should throw error if OCI trust policy is not found")
	}
}

// TestApplicableTrustPolicy tests filtering policies against registry scopes
func TestApplicableTrustPolicy(t *testing.T) {
	policyDoc := dummyOCIPolicyDocument()

	policyStatement := policyDoc.TrustPolicies[0]
	policyStatement.Name = "test-statement-name-1"
	registryScope := "registry.wabbit-networks.io/software/unsigned/net-utils"
	registryUri := fmt.Sprintf("%s@sha256:hash", registryScope)
	policyStatement.RegistryScopes = []string{registryScope}
	policyStatement.SignatureVerification = SignatureVerification{VerificationLevel: "strict"}

	policyDoc.TrustPolicies = []OCITrustPolicy{
		policyStatement,
	}
	// existing Registry Scope
	policy, err := (&policyDoc).GetApplicableTrustPolicy(registryUri)
	if policy.Name != policyStatement.Name || err != nil {
		t.Fatalf("GetApplicableTrustPolicy() should return %q for registry scope %q", policyStatement.Name, registryScope)
	}

	// non-existing Registry Scope
	policy, err = (&policyDoc).GetApplicableTrustPolicy("non.existing.scope/repo@sha256:hash")
	if policy != nil || err == nil || err.Error() != "artifact \"non.existing.scope/repo@sha256:hash\" has no applicable oci trust policy statement. Trust policy applicability for a given artifact is determined by registryScopes. To create a trust policy, see: https://notaryproject.dev/docs/quickstart/#create-a-trust-policy" {
		t.Fatalf("GetApplicableTrustPolicy() should return nil for non existing registry scope")
	}

	// wildcard registry scope
	wildcardStatement := OCITrustPolicy{
		Name:                  "test-statement-name-2",
		SignatureVerification: SignatureVerification{VerificationLevel: "skip"},
		TrustStores:           []string{},
		TrustedIdentities:     []string{},
		RegistryScopes:        []string{"*"},
	}

	policyDoc.TrustPolicies = []OCITrustPolicy{
		policyStatement,
		wildcardStatement,
	}
	policy, err = (&policyDoc).GetApplicableTrustPolicy("some.registry.that/has.no.policy@sha256:hash")
	if policy.Name != wildcardStatement.Name || err != nil {
		t.Fatalf("GetApplicableTrustPolicy() should return wildcard policy for registry scope \"some.registry.that/has.no.policy\"")
	}
}

// TestValidatePolicyDocument calls policyDoc.Validate()
// and tests various validations on policy elements
func TestValidateInvalidPolicyDocument(t *testing.T) {
	// Sanity check
	var nilPolicyDoc *OCIDocument
	err := nilPolicyDoc.Validate()
	if err == nil || err.Error() != "oci trust policy document cannot be nil" {
		t.Fatalf("nil policyDoc should return error")
	}

	// Invalid Version
	policyDoc := dummyOCIPolicyDocument()
	policyDoc.Version = "invalid"
	err = policyDoc.Validate()
	if err == nil || err.Error() != "oci trust policy document uses unsupported version \"invalid\"" {
		t.Fatalf("invalid version should return error")
	}

	// No Policy Statements
	policyDoc = dummyOCIPolicyDocument()
	policyDoc.TrustPolicies = nil
	err = policyDoc.Validate()
	if err == nil || err.Error() != "oci trust policy document can not have zero trust policy statements" {
		t.Fatalf("zero policy statements should return error")
	}

	// No Policy Statement Name
	policyDoc = dummyOCIPolicyDocument()
	policyDoc.TrustPolicies[0].Name = ""
	err = policyDoc.Validate()
	if err == nil || err.Error() != "oci trust policy: a trust policy statement is missing a name, every statement requires a name" {
		t.Fatalf("policy statement with no name should return an error")
	}

	// No Registry Scopes
	policyDoc = dummyOCIPolicyDocument()
	policyDoc.TrustPolicies[0].RegistryScopes = nil
	err = policyDoc.Validate()
	if err == nil || err.Error() != "oci trust policy statement \"test-statement-name\" has zero registry scopes, it must specify registry scopes with at least one value" {
		t.Fatalf("policy statement with registry scopes should return error")
	}

	// Multiple policy statements with same registry scope
	policyDoc = dummyOCIPolicyDocument()
	policyStatement1 := policyDoc.TrustPolicies[0].clone()
	policyStatement2 := policyDoc.TrustPolicies[0].clone()
	policyStatement2.Name = "test-statement-name-2"
	policyDoc.TrustPolicies = []OCITrustPolicy{*policyStatement1, *policyStatement2}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "registry scope \"registry.acme-rockets.io/software/net-monitor\" is present in multiple oci trust policy statements, one registry scope value can only be associated with one statement" {
		t.Fatalf("Policy statements with same registry scope should return error %q", err)
	}

	// Registry scopes with a wildcard
	policyDoc = dummyOCIPolicyDocument()
	policyDoc.TrustPolicies[0].RegistryScopes = []string{"*", "registry.acme-rockets.io/software/net-monitor"}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "oci trust policy statement \"test-statement-name\" uses wildcard registry scope '*', a wildcard scope cannot be used in conjunction with other scope values" {
		t.Fatalf("policy statement with more than a wildcard registry scope should return error")
	}

	// Invalid SignatureVerification
	policyDoc = dummyOCIPolicyDocument()
	policyDoc.TrustPolicies[0].SignatureVerification = SignatureVerification{VerificationLevel: "invalid"}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "oci trust policy: trust policy statement \"test-statement-name\" has invalid signatureVerification: invalid signature verification level \"invalid\"" {
		t.Fatalf("policy statement with invalid SignatureVerification should return error")
	}

	// Invalid SignatureVerification VerifyTimestamp
	policyDoc = dummyOCIPolicyDocument()
	policyDoc.TrustPolicies[0].SignatureVerification.VerifyTimestamp = "invalid"
	expectedErrMsg := "oci trust policy: trust policy statement \"test-statement-name\" has invalid signatureVerification: verifyTimestamp must be \"always\" or \"afterCertExpiry\", but got \"invalid\""
	err = policyDoc.Validate()
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected %s, but got %s", expectedErrMsg, err)
	}

	// strict SignatureVerification should have a trust store
	policyDoc = dummyOCIPolicyDocument()
	policyDoc.TrustPolicies[0].TrustStores = []string{}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "oci trust policy: trust policy statement \"test-statement-name\" is either missing trust stores or trusted identities, both must be specified" {
		t.Fatalf("strict SignatureVerification should have a trust store")
	}

	// strict SignatureVerification should have trusted identities
	policyDoc = dummyOCIPolicyDocument()
	policyDoc.TrustPolicies[0].TrustedIdentities = []string{}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "oci trust policy: trust policy statement \"test-statement-name\" is either missing trust stores or trusted identities, both must be specified" {
		t.Fatalf("strict SignatureVerification should have trusted identities")
	}

	// skip SignatureVerification should not have trust store or trusted identities
	policyDoc = dummyOCIPolicyDocument()
	policyDoc.TrustPolicies[0].SignatureVerification = SignatureVerification{VerificationLevel: "skip"}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "oci trust policy: trust policy statement \"test-statement-name\" is set to skip signature verification but configured with trust stores and/or trusted identities, remove them if signature verification needs to be skipped" {
		t.Fatalf("strict SignatureVerification should have trusted identities")
	}

	// Empty Trusted Identity should throw error
	policyDoc = dummyOCIPolicyDocument()
	policyDoc.TrustPolicies[0].TrustedIdentities = []string{""}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "oci trust policy: trust policy statement \"test-statement-name\" has an empty trusted identity" {
		t.Fatalf("policy statement with empty trusted identity should return error")
	}

	// Trusted Identity without separator should throw error
	policyDoc = dummyOCIPolicyDocument()
	policyDoc.TrustPolicies[0].TrustedIdentities = []string{"x509.subject"}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "oci trust policy: trust policy statement \"test-statement-name\" has trusted identity \"x509.subject\" missing separator" {
		t.Fatalf("policy statement with trusted identity missing separator should return error")
	}

	// Empty Trusted Identity value should throw error
	policyDoc = dummyOCIPolicyDocument()
	policyDoc.TrustPolicies[0].TrustedIdentities = []string{"x509.subject:"}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "oci trust policy: trust policy statement \"test-statement-name\" has trusted identity \"x509.subject:\" without an identity value" {
		t.Fatalf("policy statement with trusted identity missing identity value should return error")
	}

	// trust store/trusted identities are optional for skip SignatureVerification
	policyDoc = dummyOCIPolicyDocument()
	policyDoc.TrustPolicies[0].SignatureVerification = SignatureVerification{VerificationLevel: "skip"}
	policyDoc.TrustPolicies[0].TrustStores = []string{}
	policyDoc.TrustPolicies[0].TrustedIdentities = []string{}
	err = policyDoc.Validate()
	if err != nil {
		t.Fatalf("skip SignatureVerification should not require a trust store or trusted identities")
	}

	// Trust Store missing separator
	policyDoc = dummyOCIPolicyDocument()
	policyDoc.TrustPolicies[0].TrustStores = []string{"ca"}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "oci trust policy: trust policy statement \"test-statement-name\" has malformed trust store value \"ca\". The required format is <TrustStoreType>:<TrustStoreName>" {
		t.Fatalf("policy statement with trust store missing separator should return error")
	}

	// Invalid Trust Store type
	policyDoc = dummyOCIPolicyDocument()
	policyDoc.TrustPolicies[0].TrustStores = []string{"invalid:test-trust-store"}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "oci trust policy: trust policy statement \"test-statement-name\" uses an unsupported trust store type \"invalid\" in trust store value \"invalid:test-trust-store\"" {
		t.Fatalf("policy statement with invalid trust store type should return error")
	}

	// Empty Named Store
	policyDoc = dummyOCIPolicyDocument()
	policyDoc.TrustPolicies[0].TrustStores = []string{"ca:"}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "oci trust policy: trust policy statement \"test-statement-name\" uses an unsupported trust store name \"\" in trust store value \"ca:\". Named store name needs to follow [a-zA-Z0-9_.-]+ format" {
		t.Fatalf("policy statement with trust store missing named store should return error")
	}

	// trusted identities with a wildcard
	policyDoc = dummyOCIPolicyDocument()
	policyDoc.TrustPolicies[0].TrustedIdentities = []string{"*", "test-identity"}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "oci trust policy: trust policy statement \"test-statement-name\" uses a wildcard trusted identity '*', a wildcard identity cannot be used in conjunction with other values" {
		t.Fatalf("policy statement with more than a wildcard trusted identity should return error")
	}

	// Policy Document with duplicate policy statement names
	policyDoc = dummyOCIPolicyDocument()
	policyStatement1 = policyDoc.TrustPolicies[0].clone()
	policyStatement2 = policyDoc.TrustPolicies[0].clone()
	policyStatement2.RegistryScopes = []string{"registry.acme-rockets.io/software/legacy/metrics"}
	policyDoc.TrustPolicies = []OCITrustPolicy{*policyStatement1, *policyStatement2}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "multiple oci trust policy statements use the same name \"test-statement-name\", statement names must be unique" {
		t.Fatalf("policy statements with same name should return error")
	}
}

// TestValidRegistryScopes tests valid scopes are accepted
func TestValidRegistryScopes(t *testing.T) {
	policyDoc := dummyOCIPolicyDocument()
	validScopes := []string{
		"*", "example.com/rep", "example.com:8080/rep/rep2", "example.com/rep/subrep/subsub",
		"10.10.10.10:8080/rep/rep2", "domain/rep", "domain:1234/rep",
	}

	for _, scope := range validScopes {
		policyDoc.TrustPolicies[0].RegistryScopes = []string{scope}
		err := policyDoc.Validate()
		if err != nil {
			t.Fatalf("valid registry scope should not return error. Error : %q", err)
		}
	}
}

// TestInvalidRegistryScopes tests invalid scopes are rejected
func TestInvalidRegistryScopes(t *testing.T) {
	policyDoc := dummyOCIPolicyDocument()
	invalidScopes := []string{
		"", "1:1", "a,b", "abcd", "1111", "1,2", "example.com/rep:tag",
		"example.com/rep/subrep/sub:latest", "example.com", "rep/rep2:latest",
		"repository", "10.10.10.10", "10.10.10.10:8080/rep/rep2:latest",
	}

	for _, scope := range invalidScopes {
		policyDoc.TrustPolicies[0].RegistryScopes = []string{scope}
		err := policyDoc.Validate()
		if err == nil || err.Error() != "registry scope \""+scope+"\" is not valid, make sure it is a fully qualified repository without the scheme, protocol or tag. For example domain.com/my/repository or a local scope like local/myOCILayout" {
			t.Fatalf("invalid registry scope should return error. Error : %q", err)
		}
	}

	// Test invalid scope with wild card suffix
	invalidWildCardScopes := []string{"example.com/*", "*/", "example*/", "ex*test"}
	for _, scope := range invalidWildCardScopes {
		policyDoc.TrustPolicies[0].RegistryScopes = []string{scope}
		err := policyDoc.Validate()
		if err == nil || err.Error() != "registry scope \""+scope+"\" with wild card(s) is not valid, make sure it is a fully qualified repository without the scheme, protocol or tag. For example domain.com/my/repository or a local scope like local/myOCILayout" {
			t.Fatalf("invalid registry scope should return error. Error : %q", err)
		}
	}
}

// TestValidateValidPolicyDocument tests a happy policy document
func TestValidateValidPolicyDocument(t *testing.T) {
	policyDoc := dummyOCIPolicyDocument()

	policyStatement1 := policyDoc.TrustPolicies[0].clone()

	policyStatement2 := policyStatement1.clone()
	policyStatement2.Name = "test-statement-name-2"
	policyStatement2.RegistryScopes = []string{"registry.wabbit-networks.io/software/unsigned/net-utils"}
	policyStatement2.SignatureVerification = SignatureVerification{VerificationLevel: "permissive"}

	policyStatement3 := policyStatement1.clone()
	policyStatement3.Name = "test-statement-name-3"
	policyStatement3.RegistryScopes = []string{"registry.acme-rockets.io/software/legacy/metrics"}
	policyStatement3.TrustStores = []string{}
	policyStatement3.TrustedIdentities = []string{}
	policyStatement3.SignatureVerification = SignatureVerification{VerificationLevel: "skip"}

	policyStatement4 := policyStatement1.clone()
	policyStatement4.Name = "test-statement-name-4"
	policyStatement4.RegistryScopes = []string{"*"}
	policyStatement4.TrustStores = []string{"ca:valid-trust-store", "signingAuthority:valid-trust-store-2"}
	policyStatement4.SignatureVerification = SignatureVerification{VerificationLevel: "audit"}

	policyStatement5 := policyStatement1.clone()
	policyStatement5.Name = "test-statement-name-5"
	policyStatement5.RegistryScopes = []string{"registry.acme-rockets2.io/software"}
	policyStatement5.TrustedIdentities = []string{"*"}
	policyStatement5.SignatureVerification = SignatureVerification{VerificationLevel: "strict"}

	policyStatement6 := policyStatement1.clone()
	policyStatement6.Name = "test-statement-name-6"
	policyStatement6.RegistryScopes = []string{"registry.acme-rockets.io/software/net-monitor6"}
	policyStatement6.SignatureVerification.VerifyTimestamp = ""

	policyStatement7 := policyStatement1.clone()
	policyStatement7.Name = "test-statement-name-7"
	policyStatement7.RegistryScopes = []string{"registry.acme-rockets.io/software/net-monitor7"}
	policyStatement7.SignatureVerification.VerifyTimestamp = OptionAlways

	policyStatement8 := policyStatement1.clone()
	policyStatement8.Name = "test-statement-name-8"
	policyStatement8.RegistryScopes = []string{"registry.acme-rockets.io/software/net-monitor8"}
	policyStatement8.SignatureVerification.VerifyTimestamp = OptionAfterCertExpiry

	policyDoc.TrustPolicies = []OCITrustPolicy{
		*policyStatement1,
		*policyStatement2,
		*policyStatement3,
		*policyStatement4,
		*policyStatement5,
		*policyStatement6,
		*policyStatement7,
		*policyStatement8,
	}

	err := policyDoc.Validate()
	if err != nil {
		t.Fatalf("validation failed on a good policy document. Error : %q", err)
	}
}
