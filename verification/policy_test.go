package verification

import (
	"fmt"
	"testing"
)

func dummyPolicyStatement() (policyStatement TrustPolicy) {
	policyStatement = TrustPolicy{
		Name:                  "test-statement-name",
		RegistryScopes:        []string{"registry.acme-rockets.io/software/net-monitor"},
		SignatureVerification: "strict",
		TrustStores:           []string{"ca:valid-trust-store"},
		TrustedIdentities:     []string{"x509.subject:CN=Notation Test Leaf Cert,O=Notary,L=Seattle,ST=WA,C=US"},
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
	policyStatement2.RegistryScopes = []string{"registry.wabbit-networks.io/software/unsigned/net-utils"}
	policyStatement2.SignatureVerification = "permissive"

	policyStatement3 := dummyPolicyStatement()
	policyStatement3.Name = "test-statement-name-3"
	policyStatement3.RegistryScopes = []string{"registry.acme-rockets.io/software/legacy/metrics"}
	policyStatement3.TrustStores = []string{}
	policyStatement3.TrustedIdentities = []string{}
	policyStatement3.SignatureVerification = "skip"

	policyStatement4 := dummyPolicyStatement()
	policyStatement4.Name = "test-statement-name-4"
	policyStatement4.TrustStores = []string{"ca:valid-trust-store", "ca:valid-trust-store-2"}
	policyStatement4.RegistryScopes = []string{"*"}
	policyStatement4.SignatureVerification = "audit"

	policyStatement5 := dummyPolicyStatement()
	policyStatement5.Name = "test-statement-name-5"
	policyStatement5.RegistryScopes = []string{"registry.acme-rockets2.io/software"}
	policyStatement5.TrustedIdentities = []string{"*"}
	policyStatement5.SignatureVerification = "strict"

	policyDoc.TrustPolicies = []TrustPolicy{
		policyStatement1,
		policyStatement2,
		policyStatement3,
		policyStatement4,
		policyStatement5,
	}
	err := policyDoc.ValidatePolicyDocument()
	if err != nil {
		t.Fatalf("validation failed on a good policy document. Error : %q", err)
	}
}

// TestValidateTrustedIdentities tests only valid x509.subjects are accepted
func TestValidateTrustedIdentities(t *testing.T) {

	// No trusted identity prefix throws error
	policyDoc := dummyPolicyDocument()
	policyStatement := dummyPolicyStatement()
	policyStatement.TrustedIdentities = []string{"C=US, ST=WA, O=wabbit-network.io, OU=org1"}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err := policyDoc.ValidatePolicyDocument()
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" has trusted identity \"C=US, ST=WA, O=wabbit-network.io, OU=org1\" without an identity prefix" {
		t.Fatalf("trusted identity without a prefix should return error")
	}

	// Accept unknown identity prefixes
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.TrustedIdentities = []string{"unknown:my-trusted-idenity"}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.ValidatePolicyDocument()
	if err != nil {
		t.Fatalf("unknown identity prefix should not return an error. Error: %q", err)
	}

	// Validate x509.subject identities
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	invalidDN := "x509.subject:,,,"
	policyStatement.TrustedIdentities = []string{invalidDN}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.ValidatePolicyDocument()
	if err == nil || err.Error() != "distinguished name (DN) \",,,\" is not valid, it must contain 'C', 'ST', and 'O' RDN attributes at a minimum, and follow RFC 4514 standard" {
		t.Fatalf("invalid x509.subject identity should return error. Error : %q", err)
	}

	// Validate duplicate RDNs
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	invalidDN = "x509.subject:C=US,C=IN"
	policyStatement.TrustedIdentities = []string{invalidDN}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.ValidatePolicyDocument()
	if err == nil || err.Error() != "distinguished name (DN) \"C=US,C=IN\" has duplicate RDN attribute for \"C\", DN can only have unique RDN attributes" {
		t.Fatalf("invalid x509.subject identity should return error. Error : %q", err)
	}

	// Validate mandatory RDNs
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	invalidDN = "x509.subject:C=US,ST=WA"
	policyStatement.TrustedIdentities = []string{invalidDN}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.ValidatePolicyDocument()
	if err == nil || err.Error() != "distinguished name (DN) \"C=US,ST=WA\" has no mandatory RDN attribute for \"O\", it must contain 'C', 'ST', and 'O' RDN attributes at a minimum" {
		t.Fatalf("invalid x509.subject identity should return error. Error : %q", err)
	}

	// DN may have optional RDNs
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	validDN := "x509.subject:C=US,ST=WA,O=MyOrg,CustomRDN=CustomValue"
	policyStatement.TrustedIdentities = []string{validDN}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.ValidatePolicyDocument()
	if err != nil {
		t.Fatalf("valid x509.subject identity should not return error. Error : %q", err)
	}

	// Validate rfc4514 DNs
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	validDN1 := "x509.subject:C=US,ST=WA,O=MyOrg"
	validDN2 := "x509.subject:C=US,ST=WA,O=  My.  Org"
	validDN3 := "x509.subject:C=US,ST=WA,O=My \"special\" Org \\, \\; \\\\ others"
	validDN4 := "x509.subject:C=US,ST=WA,O=My Org,1.3.6.1.4.1.1466.0=#04024869"
	policyStatement.TrustedIdentities = []string{validDN1, validDN2, validDN3, validDN4}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.ValidatePolicyDocument()
	if err != nil {
		t.Fatalf("valid x509.subject identity should not return error. Error : %q", err)
	}

	// Validate overlapping DNs
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	validDN1 = "x509.subject:C=US,ST=WA,O=MyOrg"
	validDN2 = "x509.subject:C=US,ST=WA,O=MyOrg,X=Y"
	policyStatement.TrustedIdentities = []string{validDN1, validDN2}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.ValidatePolicyDocument()
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" has overlapping x509 trustedIdentities, \"x509.subject:C=US,ST=WA,O=MyOrg\" overlaps with \"x509.subject:C=US,ST=WA,O=MyOrg,X=Y\"" {
		t.Fatalf("overlapping DNs should return error")
	}

	// Validate multi-valued RDNs
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	multiValduedRDN := "x509.subject:C=US+ST=WA,O=MyOrg"
	policyStatement.TrustedIdentities = []string{multiValduedRDN}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.ValidatePolicyDocument()
	if err == nil || err.Error() != "distinguished name (DN) \"C=US+ST=WA,O=MyOrg\" has multi-valued RDN attributes, remove multi-valued RDN attributes as they are not supported" {
		t.Fatalf("multi-valued RDN should return error. Error : %q", err)
	}
}

// TestInvalidRegistryScopes tests invalid scopes are rejected
func TestInvalidRegistryScopes(t *testing.T) {
	invalidScopes := []string{
		"", "1:1", "a,b", "abcd", "1111", "1,2", "example.com/rep:tag",
		"example.com/rep/subrep/sub:latest", "example.com", "rep/rep2:latest",
		"repository", "10.10.10.10", "10.10.10.10:8080/rep/rep2:latest",
	}

	for _, scope := range invalidScopes {
		policyDoc := dummyPolicyDocument()
		policyStatement := dummyPolicyStatement()
		policyStatement.RegistryScopes = []string{scope}
		policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
		err := policyDoc.ValidatePolicyDocument()
		if err == nil || err.Error() != "registry scope \""+scope+"\" is not valid, make sure it is the fully qualified registry URL without the scheme/protocol. e.g domain.com/my/repository" {
			t.Fatalf("invalid registry scope should return error. Error : %q", err)
		}
	}
}

// TestValidRegistryScopes tests valid scopes are accepted
func TestValidRegistryScopes(t *testing.T) {
	validScopes := []string{
		"example.com/rep", "example.com:8080/rep/rep2", "example.com/rep/subrep/subsub",
		"10.10.10.10:8080/rep/rep2", "domain/rep", "domain:1234/rep",
	}

	for _, scope := range validScopes {
		policyDoc := dummyPolicyDocument()
		policyStatement := dummyPolicyStatement()
		policyStatement.RegistryScopes = []string{scope}
		policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
		err := policyDoc.ValidatePolicyDocument()
		if err != nil {
			t.Fatalf("valid registry scope should not return error. Error : %q", err)
		}
	}
}

// TestValidatePolicyDocument calls policyDoc.ValidatePolicyDocument()
// and tests various validations on policy eliments
func TestValidateInvalidPolicyDocument(t *testing.T) {

	// Invalid Version
	policyDoc := dummyPolicyDocument()
	policyDoc.Version = "invalid"
	err := policyDoc.ValidatePolicyDocument()
	if err == nil || err.Error() != "trust policy document uses unsupported version \"invalid\"" {
		t.Fatalf("invalid version should return error")
	}

	// No Policy Satements
	policyDoc = dummyPolicyDocument()
	policyDoc.TrustPolicies = nil
	err = policyDoc.ValidatePolicyDocument()
	if err == nil || err.Error() != "trust policy document can not have zero trust policy statements" {
		t.Fatalf("zero policy statements should return error")
	}

	// No Policy Satement Name
	policyDoc = dummyPolicyDocument()
	policyStatement := dummyPolicyStatement()
	policyStatement.Name = ""
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.ValidatePolicyDocument()
	if err == nil || err.Error() != "a trust policy statement is missing a name, every statement requires a name" {
		t.Fatalf("policy statement with no name should return an error")
	}

	// No Registry Scopes
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.RegistryScopes = nil
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.ValidatePolicyDocument()
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" has zero registry scopes, it must specify registry scopes with at least one value" {
		t.Fatalf("policy statement with registry scopes should return error")
	}

	// Multiple policy statements with same registry scope
	policyDoc = dummyPolicyDocument()
	policyStatement1 := dummyPolicyStatement()
	policyStatement2 := dummyPolicyStatement()
	policyStatement2.Name = "test-statement-name-2"
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement1, policyStatement2}
	err = policyDoc.ValidatePolicyDocument()
	if err == nil || err.Error() != "registry scope \"registry.acme-rockets.io/software/net-monitor\" is present in multiple trust policy statements, one registry scope value can only be associated with one statement" {
		t.Fatalf("Policy statements with same registry scope should return error %q", err)
	}

	// Registry scopes with a wildcard
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.RegistryScopes = []string{"*", "registry.acme-rockets.io/software/net-monitor"}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.ValidatePolicyDocument()
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" uses wildcard registry scope '*', a wildcard scope cannot be used in conjunction with other scope values" {
		t.Fatalf("policy statement with more than a wildcard registry scope should return error")
	}

	// Invlaid SignatureVerification
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.SignatureVerification = "invalid"
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.ValidatePolicyDocument()
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" uses unsupported signatureVerification value \"invalid\"" {
		t.Fatalf("policy statement with invalid SignatureVerification should return error")
	}

	// strict SignatureVerification should have a trust store
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.TrustStores = []string{}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.ValidatePolicyDocument()
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" is either missing trust stores or trusted identities, both must be specified" {
		t.Fatalf("strict SignatureVerification should have a trust store")
	}

	// strict SignatureVerification should have trusted identities
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.TrustedIdentities = []string{}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.ValidatePolicyDocument()
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" is either missing trust stores or trusted identities, both must be specified" {
		t.Fatalf("strict SignatureVerification should have trusted identities")
	}

	// skip SignatureVerification should not have trust store or trusted identities
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.SignatureVerification = "skip"
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.ValidatePolicyDocument()
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" is set to skip signature verification but configured with trust stores and/or trusted identities, remove them if signature verification needs to be skipped" {
		t.Fatalf("strict SignatureVerification should have trusted identities")
	}

	// Empty Trusted Identity should throw error
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.TrustedIdentities = []string{""}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.ValidatePolicyDocument()
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" has an empty trusted identity" {
		t.Fatalf("policy statement with empty trusted identity should return error")
	}

	// trust store/trusted identites are optional for skip SignatureVerification
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.SignatureVerification = "skip"
	policyStatement.TrustStores = []string{}
	policyStatement.TrustedIdentities = []string{}
	err = policyDoc.ValidatePolicyDocument()
	if err != nil {
		t.Fatalf("skip SignatureVerification should not require a trust store or trusted identities")
	}

	// Invalid Trust Store prefix
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.TrustStores = []string{"invalid:test-trust-store"}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.ValidatePolicyDocument()
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" uses an unsupported trust store type \"invalid\" in trust store value \"invalid:test-trust-store\"" {
		t.Fatalf("policy statement with invalid trust store type should return error")
	}

	// trusted identities with a wildcard
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.TrustedIdentities = []string{"*", "test-identity"}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.ValidatePolicyDocument()
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" uses a wildcard trusted identity '*', a wildcard identity cannot be used in conjunction with other values" {
		t.Fatalf("policy statement with more than a wildcard trusted identity should return error")
	}

	// Policy Document with duplicate policy statement names
	policyDoc = dummyPolicyDocument()
	policyStatement1 = dummyPolicyStatement()
	policyStatement2 = dummyPolicyStatement()
	policyStatement2.RegistryScopes = []string{"registry.acme-rockets.io/software/legacy/metrics"}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement1, policyStatement2}
	err = policyDoc.ValidatePolicyDocument()
	if err == nil || err.Error() != "multiple trust policy statements use the same name \"test-statement-name\", statement names must be unique" {
		t.Fatalf("policy statements with same name should return error")
	}
}

// TestApplicableTrustPolicy tests filtering policies against registry scopes
func TestApplicableTrustPolicy(t *testing.T) {
	policyDoc := dummyPolicyDocument()

	policyStatement := dummyPolicyStatement()
	policyStatement.Name = "test-statement-name-1"
	registryScope := "registry.wabbit-networks.io/software/unsigned/net-utils"
	registryUri := fmt.Sprintf("%s@sha256:hash", registryScope)
	policyStatement.RegistryScopes = []string{registryScope}
	policyStatement.SignatureVerification = "strict"

	policyDoc.TrustPolicies = []TrustPolicy{
		policyStatement,
	}
	// existing Registry Scope
	policy, err := policyDoc.getApplicableTrustPolicy(registryUri)
	if policy.Name != policyStatement.Name || err != nil {
		t.Fatalf("getApplicableTrustPolicy should return %q for registry scope %q", policyStatement.Name, registryScope)
	}

	// non-existing Registry Scope
	policy, err = policyDoc.getApplicableTrustPolicy("non.existing.scope/repo@sha256:hash")
	if policy != nil || err == nil || err.Error() != "artifact \"non.existing.scope/repo@sha256:hash\" has no applicable trust policy" {
		t.Fatalf("getApplicableTrustPolicy should return nil for non existing registry scope")
	}

	// wildcard registry scope
	wildcardStatement := dummyPolicyStatement()
	wildcardStatement.Name = "test-statement-name-2"
	wildcardStatement.RegistryScopes = []string{"*"}
	wildcardStatement.TrustStores = []string{}
	wildcardStatement.TrustedIdentities = []string{}
	wildcardStatement.SignatureVerification = "skip"

	policyDoc.TrustPolicies = []TrustPolicy{
		policyStatement,
		wildcardStatement,
	}
	policy, err = policyDoc.getApplicableTrustPolicy("some.registry.that/has.no.policy@sha256:hash")
	if policy.Name != wildcardStatement.Name || err != nil {
		t.Fatalf("getApplicableTrustPolicy should return wildcard policy for registry scope \"some.registry.that/has.no.policy\"")
	}
}
