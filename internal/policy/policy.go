package policy

import (
	"fmt"
	"strings"

	"github.com/notaryproject/notation-go/internal/common"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
)

// getApplicableTrustPolicy returns a pointer to the deep copied TrustPolicy statement that applies to the given
// registry URI. If no applicable trust policy is found, returns an error
// see https://github.com/notaryproject/notaryproject/blob/main/trust-store-trust-policy-specification.md#selecting-a-trust-policy-based-on-artifact-uri
func GetApplicableTrustPolicy(trustPolicyDoc *trustpolicy.Document, artifactReference string) (*trustpolicy.TrustPolicy, error) {

	artifactPath, err := getArtifactPathFromReference(artifactReference)
	if err != nil {
		return nil, err
	}

	var wildcardPolicy *trustpolicy.TrustPolicy
	var applicablePolicy *trustpolicy.TrustPolicy
	for _, policyStatement := range trustPolicyDoc.TrustPolicies {
		if common.IsPresent(common.Wildcard, policyStatement.RegistryScopes) {
			wildcardPolicy = deepCopy(&policyStatement) // we need to deep copy because we can't use the loop variable address. see https://stackoverflow.com/a/45967429
		} else if common.IsPresent(artifactPath, policyStatement.RegistryScopes) {
			applicablePolicy = deepCopy(&policyStatement)
		}
	}

	if applicablePolicy != nil {
		// a policy with exact match for registry URI takes precedence over a wildcard (*) policy.
		return applicablePolicy, nil
	} else if wildcardPolicy != nil {
		return wildcardPolicy, nil
	} else {
		return nil, fmt.Errorf("artifact %q has no applicable trust policy", artifactReference)
	}
}

// deepCopy returns a pointer to the deeply copied TrustPolicy
func deepCopy(t *trustpolicy.TrustPolicy) *trustpolicy.TrustPolicy {
	return &trustpolicy.TrustPolicy{
		Name:                  t.Name,
		SignatureVerification: t.SignatureVerification,
		RegistryScopes:        append([]string(nil), t.RegistryScopes...),
		TrustedIdentities:     append([]string(nil), t.TrustedIdentities...),
		TrustStores:           append([]string(nil), t.TrustStores...),
	}
}

func getArtifactPathFromReference(artifactReference string) (string, error) {
	// TODO support more types of URI like "domain.com/repository", "domain.com/repository:tag"
	i := strings.LastIndex(artifactReference, "@")
	if i < 0 {
		return "", fmt.Errorf("artifact URI %q could not be parsed, make sure it is the fully qualified OCI artifact URI without the scheme/protocol. e.g domain.com:80/my/repository@sha256:digest", artifactReference)
	}

	artifactPath := artifactReference[:i]
	if err := common.ValidateRegistryScopeFormat(artifactPath); err != nil {
		return "", err
	}
	return artifactPath, nil
}
