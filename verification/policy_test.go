package verification

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"
)

func dummyPolicyStatement() (policyStatement TrustPolicy) {
	policyStatement = TrustPolicy{
		Name:                  "test-statement-name",
		RegistryScopes:        []string{"test-registry-scope"},
		SignatureVerification: "strict",
		TrustStore:            "ca:test-store",
		TrustedIdentities:     []string{"test-identity"},
	}
	return
}

func dummyPolicyDocument() (policyDoc PolicyDocument) {
	policyDoc = PolicyDocument{
		Version:       "1.0",
		TrustPolicies: []TrustPolicy{dummyPolicyStatement()},
	}
	return
}

func writeToTempFile(policyDoc PolicyDocument) string {
	tmpFile, _ := ioutil.TempFile(os.TempDir(), "notation-test-")
	file, _ := json.MarshalIndent(policyDoc, "", " ")
	_ = ioutil.WriteFile(tmpFile.Name(), file, 0644)
	return tmpFile.Name()
}

// TestLoadPolicyDocument calls verification.LoadPolicyDocument with a path, checking
// it succeeds in the happy path.
func TestLoadValidFile(t *testing.T) {
	path := writeToTempFile(dummyPolicyDocument())
	defer os.Remove(path)
	_, err := LoadPolicyDocument(path)
	if err != nil {
		t.Fatalf("Could not load the trust policy file")
	}
}

// TestLoadPolicyDocument calls verification.LoadPolicyDocument with an invalid path
func TestLoadInvalidFile(t *testing.T) {
	policyDoc, _ := LoadPolicyDocument("path")
	if policyDoc != nil {
		t.Fatalf("Loaded an invalid trust policy file")
	}
}

// TestValidateValidPolicyDocument tests a happy policy document
func TestValidateValidPolicyDocument(t *testing.T) {
	policyDoc := dummyPolicyDocument()

	policyStatement1 := dummyPolicyStatement()

	policyStatement2 := dummyPolicyStatement()
	policyStatement2.Name = "test-statement-name-2"
	policyStatement2.RegistryScopes = []string{"test-registry-scope-2"}
	policyStatement2.SignatureVerification = "permissive"

	policyStatement3 := dummyPolicyStatement()
	policyStatement3.Name = "test-statement-name-3"
	policyStatement3.RegistryScopes = []string{"test-registry-scope-3"}
	policyStatement3.SignatureVerification = "skip"

	policyStatement4 := dummyPolicyStatement()
	policyStatement4.Name = "test-statement-name-4"
	policyStatement4.RegistryScopes = []string{"*"}
	policyStatement4.SignatureVerification = "audit"

	policyDoc.TrustPolicies = []TrustPolicy{
		policyStatement1,
		policyStatement2,
		policyStatement3,
		policyStatement4,
	}
	err := ValidatePolicyDocument(&policyDoc)
	if err != nil {
		t.Fatalf("Validation failed on a good policy document")
	}
}

// TestValidatePolicyDocument calls verification.ValidatePolicyDocument
// and tests various validations
func TestValidateInvalidPolicyDocument(t *testing.T) {

	// Invalid Version
	policyDoc := dummyPolicyDocument()
	policyDoc.Version = "invalid"
	err := ValidatePolicyDocument(&policyDoc)
	if err == nil || err.Error() != "Version 'invalid' is not supported" {
		t.Fatalf("Invalid version should return error")
	}

	// No Policy Satements
	policyDoc = dummyPolicyDocument()
	policyDoc.TrustPolicies = nil
	err = ValidatePolicyDocument(&policyDoc)
	if err == nil || err.Error() != "Trust Policy document can not have zero statements" {
		t.Fatalf("Zero policy statements should return error")
	}

	// No Policy Satement Name
	policyDoc = dummyPolicyDocument()
	policyStatement := dummyPolicyStatement()
	policyStatement.Name = ""
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = ValidatePolicyDocument(&policyDoc)
	if err == nil || err.Error() != "Policy statement is missing a name" {
		t.Fatalf("Policy statement with no name should return error")
	}

	// No Registry Scopes
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.RegistryScopes = nil
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = ValidatePolicyDocument(&policyDoc)
	if err == nil || err.Error() != "Policy statement has zero registry scopes" {
		t.Fatalf("Policy statement with registry scopes should return error")
	}

	// Multiple policy statements with same registry scope
	policyDoc = dummyPolicyDocument()
	policyStatement1 := dummyPolicyStatement()
	policyStatement2 := dummyPolicyStatement()
	policyStatement2.Name = "test-statement-name-2"
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement1, policyStatement2}
	err = ValidatePolicyDocument(&policyDoc)
	if err == nil || err.Error() != "Registry 'test-registry-scope' is present in multiple statements" {
		t.Fatalf("Policy statements with same registry scope should return error")
	}

	// Registry scopes with a wildcard
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.RegistryScopes = []string{"*", "test-registry-scope"}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = ValidatePolicyDocument(&policyDoc)
	if err == nil || err.Error() != "Wildcard scope can not be shared with other registry scopes" {
		t.Fatalf("Policy statement with more than a wildcard registry scope should return error")
	}

	// Invlaid SignatureVerification
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.SignatureVerification = "invalid"
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = ValidatePolicyDocument(&policyDoc)
	if err == nil || err.Error() != "SignatureVerification 'invalid' is not supported" {
		t.Fatalf("Policy statement with invalid SignatureVerification should return error")
	}

	// strict SignatureVerification should have a trust store
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.TrustStore = ""
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = ValidatePolicyDocument(&policyDoc)
	if err == nil || err.Error() != "Verification statement with strict or permissive preset is missing a trust store" {
		t.Fatalf("strict SignatureVerification should have a trust store")
	}

	// Invalid Trust Store prefix
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.TrustStore = "invalid:test-trust-store"
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = ValidatePolicyDocument(&policyDoc)
	if err == nil || err.Error() != "Statement 'test-statement-name' has a trust store with an unsupported trust store type" {
		t.Fatalf("Policy statement with invalid trust store type should return error")
	}

	// Empty Trusted Identity
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.TrustedIdentities = []string{""}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = ValidatePolicyDocument(&policyDoc)
	if err == nil || err.Error() != "Policy statement has an empty trusted identity" {
		t.Fatalf("Policy statement with empty trusted identity should return error")
	}

	// Policy Document with duplicate policy statement names
	policyDoc = dummyPolicyDocument()
	policyStatement1 = dummyPolicyStatement()
	policyStatement2 = dummyPolicyStatement()
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement1, policyStatement2}
	err = ValidatePolicyDocument(&policyDoc)
	if err == nil || err.Error() != "Multiple policy statements have the same name" {
		t.Fatalf("Policy statements with same name should return error")
	}
}
