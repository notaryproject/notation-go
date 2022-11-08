package policy

import (
	"fmt"
	"testing"

	"github.com/notaryproject/notation-go/verification/trustpolicy"
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

// TestApplicableTrustPolicy tests filtering policies against registry scopes
func TestApplicableTrustPolicy(t *testing.T) {
	policyDoc := dummyPolicyDocument()

	policyStatement := dummyPolicyStatement()
	policyStatement.Name = "test-statement-name-1"
	registryScope := "registry.wabbit-networks.io/software/unsigned/net-utils"
	registryUri := fmt.Sprintf("%s@sha256:hash", registryScope)
	policyStatement.RegistryScopes = []string{registryScope}
	policyStatement.SignatureVerification = trustpolicy.SignatureVerification{VerificationLevel: "strict"}

	policyDoc.TrustPolicies = []trustpolicy.TrustPolicy{
		policyStatement,
	}
	// existing Registry Scope
	policy, err := GetApplicableTrustPolicy(&policyDoc, registryUri)
	if policy.Name != policyStatement.Name || err != nil {
		t.Fatalf("getApplicableTrustPolicy should return %q for registry scope %q", policyStatement.Name, registryScope)
	}

	// non-existing Registry Scope
	policy, err = GetApplicableTrustPolicy(&policyDoc, "non.existing.scope/repo@sha256:hash")
	if policy != nil || err == nil || err.Error() != "artifact \"non.existing.scope/repo@sha256:hash\" has no applicable trust policy" {
		t.Fatalf("getApplicableTrustPolicy should return nil for non existing registry scope")
	}

	// wildcard registry scope
	wildcardStatement := dummyPolicyStatement()
	wildcardStatement.Name = "test-statement-name-2"
	wildcardStatement.RegistryScopes = []string{"*"}
	wildcardStatement.TrustStores = []string{}
	wildcardStatement.TrustedIdentities = []string{}
	wildcardStatement.SignatureVerification = trustpolicy.SignatureVerification{VerificationLevel: "skip"}

	policyDoc.TrustPolicies = []trustpolicy.TrustPolicy{
		policyStatement,
		wildcardStatement,
	}
	policy, err = GetApplicableTrustPolicy(&policyDoc, "some.registry.that/has.no.policy@sha256:hash")
	if policy.Name != wildcardStatement.Name || err != nil {
		t.Fatalf("getApplicableTrustPolicy should return wildcard policy for registry scope \"some.registry.that/has.no.policy\"")
	}
}
