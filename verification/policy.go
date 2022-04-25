/*
Package verification provides the utilities for handling verification related logic
like Trust Stores and Trust Policies. Few utilities include loading, parsing, and validating
trust policies and trust stores.
*/
package verification

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"strings"
)

// PolicyDocument represent a trust_policy.json document
type PolicyDocument struct {
	// Version of the policy document
	Version string `json:"version"`
	// TrustPolicies include each policy statement
	TrustPolicies []TrustPolicy `json:"trustPolicies"`
}

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
	wildcardScope := "*"
	supportedPolicyVersions := []string{"1.0"}
	supportedVerificationPresets := []string{"strict", "permissive", "audit", "skip"}
	supportedTrustStorePrefixes := []string{"ca", "signingservice"}

	// Validate Version
	if !isPresent(policyDoc.Version, supportedPolicyVersions) {
		return errors.New("Version '" + policyDoc.Version + "' is not supported")
	}

	// Validate the policy according to 1.0 rules
	if len(policyDoc.TrustPolicies) == 0 {
		return errors.New("Trust Policy document can not have zero statements")
	}
	var uniqueStatementNames []string
	registryScopeCount := make(map[string]int)
	for _, statement := range policyDoc.TrustPolicies {

		// Verify statement name is valid
		if statement.Name == "" {
			return errors.New("Policy statement is missing a name")
		} else {
			if !isPresent(statement.Name, uniqueStatementNames) {
				uniqueStatementNames = append(uniqueStatementNames, statement.Name)
			}
		}

		// Verify registry scopes are valid
		if len(statement.RegistryScopes) == 0 {
			return errors.New("Policy statement has zero registry scopes")
		} else {
			if len(statement.RegistryScopes) > 1 && isPresent(wildcardScope, statement.RegistryScopes) {
				return errors.New("Wildcard scope can not be shared with other registry scopes")
			}
			for _, scope := range statement.RegistryScopes {
				registryScopeCount[scope]++
			}
		}

		// Verify signature verification preset is valid
		if !isPresent(statement.SignatureVerification, supportedVerificationPresets) {
			return errors.New("SignatureVerification '" + statement.SignatureVerification + "' is not supported")
		}

		// strict and permissive verification needs trust store to verify authenticity
		if statement.SignatureVerification == "strict" || statement.SignatureVerification == "permissive" {
			if statement.TrustStore == "" {
				return errors.New("Verification statement with strict or permissive preset is missing a trust store")
			}
		}

		// Verify trust store type is valid
		if statement.TrustStore != "" {
			i := strings.Index(statement.TrustStore, ":")
			if i < 0 || !isPresent(statement.TrustStore[:i], supportedTrustStorePrefixes) {
				return errors.New("Statement '" + statement.Name + "' has a trust store with an unsupported trust store type")
			}
		}

		// If there are trusted identitied, verify they are not empty
		if len(statement.TrustedIdentities) > 0 {
			for _, identity := range statement.TrustedIdentities {
				if identity == "" {
					return errors.New("Policy statement has an empty trusted identity")
				}
			}
		}
	}

	// Verify unique policy statement names across the policy document
	if len(policyDoc.TrustPolicies) != len(uniqueStatementNames) {
		return errors.New("Multiple policy statements have the same name")
	}

	// Verify one policy statement per registry scope
	for key := range registryScopeCount {
		if registryScopeCount[key] > 1 {
			return errors.New("Registry '" + key + "' is present in multiple statements")
		}
	}

	// No errors
	return nil
}

// LoadPolicyDocument loads a policy document from the given path
// If successful, returns a pointer to the PolicyDocument. Otherwise, an error
func LoadPolicyDocument(path string) (*PolicyDocument, error) {
	jsonFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)
	var policyDoc *PolicyDocument

	err = json.Unmarshal(byteValue, &policyDoc)
	if err != nil {
		return nil, err
	}

	return policyDoc, nil
}
