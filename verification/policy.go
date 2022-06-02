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

const (
	wildcard    = "*"
	x509Subject = "x509.subject"
)

// PolicyDocument represents a trustPolicy.json document
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
	// TrustStore this policy statement uses
	TrustStore string `json:"trustStore,omitempty"`
	// TrustedIdentities this policy statement pins
	TrustedIdentities []string `json:"trustedIdentities,omitempty"`
}

// Internal type to hold raw and parsed Distinguished Names
type parsedDN struct {
	RawString string
	ParsedMap map[string]string
}

// validateRegistryScopes validates if the policy document is following the Notary V2 spec rules for registry scopes
func validateRegistryScopes(policyDoc *PolicyDocument) error {
	registryScopeCount := make(map[string]int)

	for _, statement := range policyDoc.TrustPolicies {
		// Verify registry scopes are valid
		if len(statement.RegistryScopes) == 0 {
			return fmt.Errorf("trust policy statement %q has zero registry scopes, it must specify registry scopes with at least one value", statement.Name)
		}
		if len(statement.RegistryScopes) > 1 && isPresent(wildcard, statement.RegistryScopes) {
			return fmt.Errorf("trust policy statement %q uses wildcard registry scope '*', a wildcard scope cannot be used in conjunction with other scope values", statement.Name)
		}
		for _, scope := range statement.RegistryScopes {
			if scope != wildcard {
				if err := validateRegistryScopeFormat(scope); err != nil {
					return err
				}
			}
			registryScopeCount[scope]++
		}
	}

	// Verify one policy statement per registry scope
	for key := range registryScopeCount {
		if registryScopeCount[key] > 1 {
			return fmt.Errorf("registry scope %q is present in multiple trust policy statements, one registry scope value can only be associated with one statement", key)
		}
	}

	// No error
	return nil
}

// validateRegistryScopes validates if the policy statement is following the Notary V2 spec rules for trusted identities
func validateTrustedIdentities(statement TrustPolicy) error {

	// If there is a wildcard in trusted identies, there shouldn't be any other identities
	if len(statement.TrustedIdentities) > 1 && isPresent(wildcard, statement.TrustedIdentities) {
		return fmt.Errorf("trust policy statement %q uses a wildcard trusted identity '*', a wildcard identity cannot be used in conjunction with other values", statement.Name)
	}

	var parsedDNs []parsedDN
	// If there are trusted identities, verify they are valid
	for _, identity := range statement.TrustedIdentities {
		if identity == "" {
			return fmt.Errorf("trust policy statement %q has an empty trusted identity", statement.Name)
		}

		if identity != wildcard {
			i := strings.Index(identity, ":")
			if i < 0 {
				return fmt.Errorf("trust policy statement %q has trusted identity %q without an identity prefix", statement.Name, identity)
			}

			identityPrefix := identity[:i]
			identityValue := identity[i+1:]

			// notation natively supports x509.subject identities only
			if identityPrefix == x509Subject {
				validatedDN, err := validateDistinguishedName(identityValue)
				if err != nil {
					return err
				}
				parsedDNs = append(parsedDNs, parsedDN{RawString: identity, ParsedMap: validatedDN})
			}
		}
	}

	// Verify there are no overlapping DNs
	if err := validateOverlappingDNs(statement.Name, parsedDNs); err != nil {
		return err
	}

	// No error
	return nil
}

// validateTrustStore validates if the policy statement is following the Notary V2 spec rules for truststores
func validateTrustStore(statement TrustPolicy) error {
	supportedTrustStorePrefixes := []string{"ca"}

	i := strings.Index(statement.TrustStore, ":")
	if i < 0 || !isPresent(statement.TrustStore[:i], supportedTrustStorePrefixes) {
		return fmt.Errorf("trust policy statement %q uses an unsupported trust store type %q in trust store value %q", statement.Name, statement.TrustStore[:i], statement.TrustStore)
	}

	return nil
}

// ValidatePolicyDocument validates a policy document according to it's version's rule set.
// if any rule is violated, returns an error
func ValidatePolicyDocument(policyDoc *PolicyDocument) error {
	// Constants
	supportedPolicyVersions := []string{"1.0"}
	supportedVerificationPresets := []string{"strict", "permissive", "audit", "skip"}

	// Validate Version
	if !isPresent(policyDoc.Version, supportedPolicyVersions) {
		return fmt.Errorf("trust policy document uses unsupported version %q", policyDoc.Version)
	}

	// Validate the policy according to 1.0 rules
	if len(policyDoc.TrustPolicies) == 0 {
		return errors.New("trust policy document can not have zero trust policy statements")
	}

	policyStatementNameCount := make(map[string]int)

	for _, statement := range policyDoc.TrustPolicies {

		// Verify statement name is valid
		if statement.Name == "" {
			return errors.New("a trust policy statement is missing a name, every statement requires a name")
		}
		policyStatementNameCount[statement.Name]++

		// Verify signature verification preset is valid
		if !isPresent(statement.SignatureVerification, supportedVerificationPresets) {
			return fmt.Errorf("trust policy statement %q uses unsupported signatureVerification value %q", statement.Name, statement.SignatureVerification)
		}

		// Any signature verification other than "skip" needs a trust store and trusted identities
		if statement.SignatureVerification == "skip" {
			if statement.TrustStore != "" || len(statement.TrustedIdentities) > 0 {
				return fmt.Errorf("trust policy statement %q is set to skip signature verification but configured with a trust store or trusted identities, remove them if signature verification needs to be skipped", statement.Name)
			}
		} else {
			if statement.TrustStore == "" || len(statement.TrustedIdentities) == 0 {
				return fmt.Errorf("trust policy statement %q is either missing a trust store or trusted identities, both must be specified", statement.Name)
			}

			// Verify Trust Store is valid
			if err := validateTrustStore(statement); err != nil {
				return err
			}

			// Verify Trusted Identities are valid
			if err := validateTrustedIdentities(statement); err != nil {
				return err
			}
		}

	}

	// Verify registry scopes are valid
	if err := validateRegistryScopes(policyDoc); err != nil {
		return err
	}

	// Verify unique policy statement names across the policy document
	for key := range policyStatementNameCount {
		if policyStatementNameCount[key] > 1 {
			return fmt.Errorf("multiple trust policy statements use the same name %q, statement names must be unique", key)
		}
	}

	// No errors
	return nil
}
