/*
Package verification provides the utilities for handling verification related logic
like Trust Stores and Trust Policies. Few utilities include loading, parsing, and validating
trust policies and trust stores.
*/
package verification

import (
	"errors"
	"fmt"
	"strings"
)

// PolicyDocument represents a trust_policy.json document
type PolicyDocument struct {
	// Version of the policy document
	Version string `json:"version"`
	// TrustPolicies include each policy statement
	TrustPolicies []TrustPolicy `json:"trustPolicies"`
}

// TrustPolicy represents a policy statement in the policy document
type TrustPolicy struct {
	// Name of the policy statement
	Name string `json:"name"`
	// RegistryScopes that this policy statement affects
	RegistryScopes []string `json:"registryScopes"`
	// SignatureVerification setting for this policy statement
	SignatureVerification string `json:"signatureVerification"`
	// TrustStore this policy stament uses
	TrustStore string `json:"trustStore,omitempty"`
	// TrustedIdentities this policy statement pins
	TrustedIdentities []string `json:"trustedIdentities,omitempty"`
}

func isPresent(val string, values []string) bool {
	for _, v := range values {
		if v == val {
			return true
		}
	}
	return false
}

// ValidatePolicyDocument validates a policy document according to it's version's rule set.
// if any rule is violated, returns an error
func ValidatePolicyDocument(policyDoc *PolicyDocument) error {
	// Constants
	wildcard := "*"
	supportedPolicyVersions := []string{"1.0"}
	supportedVerificationPresets := []string{"strict", "permissive", "audit", "skip"}
	supportedTrustStorePrefixes := []string{"ca", "signingservice"}

	// Validate Version
	if !isPresent(policyDoc.Version, supportedPolicyVersions) {
		return fmt.Errorf("version '%s' is not supported", policyDoc.Version)
	}

	// Validate the policy according to 1.0 rules
	if len(policyDoc.TrustPolicies) == 0 {
		return errors.New("trust policy document can not have zero policy statements")
	}
	policyStatementNameCount := make(map[string]int)
	registryScopeCount := make(map[string]int)
	for _, statement := range policyDoc.TrustPolicies {

		// Verify statement name is valid
		if statement.Name == "" {
			return errors.New("policy statement is missing a name")
		}
		policyStatementNameCount[statement.Name]++

		// Verify registry scopes are valid
		if len(statement.RegistryScopes) == 0 {
			return fmt.Errorf("policy statement '%s' has zero registry scopes", statement.Name)
		}
		if len(statement.RegistryScopes) > 1 && isPresent(wildcard, statement.RegistryScopes) {
			return errors.New("wildcard registry scope can not be shared with other registries")
		}
		for _, scope := range statement.RegistryScopes {
			registryScopeCount[scope]++
		}

		// Verify signature verification preset is valid
		if !isPresent(statement.SignatureVerification, supportedVerificationPresets) {
			return fmt.Errorf("signatureVerification '%s' is not supported", statement.SignatureVerification)
		}

		// Any signature verification other than "skip" needs a trust store
		if statement.SignatureVerification != "skip" && (statement.TrustStore == "" || len(statement.TrustedIdentities) == 0) {
			return fmt.Errorf("'%s' is either missing a trust store or trusted identities", statement.Name)
		}

		// Verify trust store type is valid
		if statement.TrustStore != "" {
			i := strings.Index(statement.TrustStore, ":")
			if i < 0 || !isPresent(statement.TrustStore[:i], supportedTrustStorePrefixes) {
				return fmt.Errorf("'%s' has a trust store with an unsupported trust store type", statement.Name)
			}
		}

		// If there are trusted identities, verify they are not empty
		for _, identity := range statement.TrustedIdentities {
			if identity == "" {
				return fmt.Errorf("'%s' has an empty trusted identity", statement.Name)
			}
		}
		// If there is a wildcard in trusted identies, there shouldn't be any other identities
		if len(statement.TrustedIdentities) > 1 && isPresent(wildcard, statement.TrustedIdentities) {
			return errors.New("wildcard trusted identity can not be shared with other identities")
		}
	}

	// Verify unique policy statement names across the policy document
	for key := range policyStatementNameCount {
		if policyStatementNameCount[key] > 1 {
			return fmt.Errorf("multiple policy statements with same name : %s", key)
		}
	}

	// Verify one policy statement per registry scope
	for key := range registryScopeCount {
		if registryScopeCount[key] > 1 {
			return fmt.Errorf("registry '%s' is present in multiple policy statements", key)
		}
	}

	// No errors
	return nil
}
