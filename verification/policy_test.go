package verification

import (
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
		t.Fatalf("validation failed on a good policy document")
	}
}

// TestValidatePolicyDocument calls verification.ValidatePolicyDocument
// and tests various validations
func TestValidateInvalidPolicyDocument(t *testing.T) {

	// Invalid Version
	policyDoc := dummyPolicyDocument()
	policyDoc.Version = "invalid"
	err := ValidatePolicyDocument(&policyDoc)
	if err == nil || err.Error() != "version 'invalid' is not supported" {
		t.Fatalf("invalid version should return error")
	}

	// No Policy Satements
	policyDoc = dummyPolicyDocument()
	policyDoc.TrustPolicies = nil
	err = ValidatePolicyDocument(&policyDoc)
	if err == nil || err.Error() != "trust policy document can not have zero policy statements" {
		t.Fatalf("zero policy statements should return error")
	}

	// No Policy Satement Name
	policyDoc = dummyPolicyDocument()
	policyStatement := dummyPolicyStatement()
	policyStatement.Name = ""
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = ValidatePolicyDocument(&policyDoc)
	if err == nil || err.Error() != "policy statement is missing a name" {
		t.Fatalf("policy statement with no name should return an error")
	}

	// No Registry Scopes
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.RegistryScopes = nil
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = ValidatePolicyDocument(&policyDoc)
	if err == nil || err.Error() != "policy statement 'test-statement-name' has zero registry scopes" {
		t.Fatalf("policy statement with registry scopes should return error")
	}

	// Multiple policy statements with same registry scope
	policyDoc = dummyPolicyDocument()
	policyStatement1 := dummyPolicyStatement()
	policyStatement2 := dummyPolicyStatement()
	policyStatement2.Name = "test-statement-name-2"
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement1, policyStatement2}
	err = ValidatePolicyDocument(&policyDoc)
	if err == nil || err.Error() != "registry 'test-registry-scope' is present in multiple policy statements" {
		t.Fatalf("Policy statements with same registry scope should return error")
	}

	// Registry scopes with a wildcard
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.RegistryScopes = []string{"*", "test-registry-scope"}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = ValidatePolicyDocument(&policyDoc)
	if err == nil || err.Error() != "wildcard registry scope can not be shared with other registries" {
		t.Fatalf("policy statement with more than a wildcard registry scope should return error")
	}

	// Invlaid SignatureVerification
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.SignatureVerification = "invalid"
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = ValidatePolicyDocument(&policyDoc)
	if err == nil || err.Error() != "signatureVerification 'invalid' is not supported" {
		t.Fatalf("policy statement with invalid SignatureVerification should return error")
	}

	// strict SignatureVerification should have a trust store
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.TrustStore = ""
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = ValidatePolicyDocument(&policyDoc)
	if err == nil || err.Error() != "'test-statement-name' is either missing a trust store or trusted identities" {
		t.Fatalf("strict SignatureVerification should have a trust store")
	}

	// strict SignatureVerification should have trusted identities
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.TrustedIdentities = []string{}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = ValidatePolicyDocument(&policyDoc)
	if err == nil || err.Error() != "'test-statement-name' is either missing a trust store or trusted identities" {
		t.Fatalf("strict SignatureVerification should have trusted identities")
	}

	// Empty Trusted Identity should throw error
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.TrustedIdentities = []string{""}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = ValidatePolicyDocument(&policyDoc)
	if err == nil || err.Error() != "'test-statement-name' has an empty trusted identity" {
		t.Fatalf("policy statement with empty trusted identity should return error")
	}

	// trust store/trusted identites are optional for skip SignatureVerification
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.SignatureVerification = "skip"
	policyStatement.TrustStore = ""
	policyStatement.TrustedIdentities = []string{}
	err = ValidatePolicyDocument(&policyDoc)
	if err != nil {
		t.Fatalf("skip SignatureVerification should not require a trust store or trusted identities")
	}

	// Invalid Trust Store prefix
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.TrustStore = "invalid:test-trust-store"
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = ValidatePolicyDocument(&policyDoc)
	if err == nil || err.Error() != "'test-statement-name' has a trust store with an unsupported trust store type" {
		t.Fatalf("policy statement with invalid trust store type should return error")
	}

	// trusted identities with a wildcard
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.TrustedIdentities = []string{"*", "test-identity"}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = ValidatePolicyDocument(&policyDoc)
	if err == nil || err.Error() != "wildcard trusted identity can not be shared with other identities" {
		t.Fatalf("policy statement with more than a wildcard trusted identity should return error")
	}

	// Policy Document with duplicate policy statement names
	policyDoc = dummyPolicyDocument()
	policyStatement1 = dummyPolicyStatement()
	policyStatement2 = dummyPolicyStatement()
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement1, policyStatement2}
	err = ValidatePolicyDocument(&policyDoc)
	if err == nil || err.Error() != "multiple policy statements with same name : test-statement-name" {
		t.Fatalf("policy statements with same name should return error")
	}
}
