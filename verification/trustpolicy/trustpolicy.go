package trustpolicy

import (
	"errors"
	"fmt"
	"strings"

	"github.com/notaryproject/notation-go/internal/common"
	"github.com/notaryproject/notation-go/verification/truststore"
)

// ValidationType is an enum for signature verification types such as Integrity, Authenticity, etc.
type ValidationType string

// ValidationAction is an enum for signature verification actions such as Enforced, Logged, Skipped.
type ValidationAction string

// VerificationLevel encapsulates the signature verification preset and it's actions for each verification type
type VerificationLevel struct {
	Name        string
	Enforcement map[ValidationType]ValidationAction
}

const (
	TypeIntegrity          ValidationType = "integrity"
	TypeAuthenticity       ValidationType = "authenticity"
	TypeAuthenticTimestamp ValidationType = "authenticTimestamp"
	TypeExpiry             ValidationType = "expiry"
	TypeRevocation         ValidationType = "revocation"

	ActionEnforce ValidationAction = "enforce"
	ActionLog     ValidationAction = "log"
	ActionSkip    ValidationAction = "skip"
)

var (
	LevelStrict = &VerificationLevel{
		Name: "strict",
		Enforcement: map[ValidationType]ValidationAction{
			TypeIntegrity:          ActionEnforce,
			TypeAuthenticity:       ActionEnforce,
			TypeAuthenticTimestamp: ActionEnforce,
			TypeExpiry:             ActionEnforce,
			TypeRevocation:         ActionEnforce,
		},
	}

	LevelPermissive = &VerificationLevel{
		Name: "permissive",
		Enforcement: map[ValidationType]ValidationAction{
			TypeIntegrity:          ActionEnforce,
			TypeAuthenticity:       ActionEnforce,
			TypeAuthenticTimestamp: ActionLog,
			TypeExpiry:             ActionLog,
			TypeRevocation:         ActionLog,
		},
	}

	LevelAudit = &VerificationLevel{
		Name: "audit",
		Enforcement: map[ValidationType]ValidationAction{
			TypeIntegrity:          ActionEnforce,
			TypeAuthenticity:       ActionLog,
			TypeAuthenticTimestamp: ActionLog,
			TypeExpiry:             ActionLog,
			TypeRevocation:         ActionLog,
		},
	}

	LevelSkip = &VerificationLevel{
		Name: "skip",
		Enforcement: map[ValidationType]ValidationAction{
			TypeIntegrity:          ActionSkip,
			TypeAuthenticity:       ActionSkip,
			TypeAuthenticTimestamp: ActionSkip,
			TypeExpiry:             ActionSkip,
			TypeRevocation:         ActionSkip,
		},
	}

	ValidationTypes = []ValidationType{
		TypeIntegrity,
		TypeAuthenticity,
		TypeAuthenticTimestamp,
		TypeExpiry,
		TypeRevocation,
	}

	ValidationActions = []ValidationAction{
		ActionEnforce,
		ActionLog,
		ActionSkip,
	}

	VerificationLevels = []*VerificationLevel{
		LevelStrict,
		LevelPermissive,
		LevelAudit,
		LevelSkip,
	}
)

// Document represents a trustPolicy.json document
type Document struct {
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
	SignatureVerification SignatureVerification `json:"signatureVerification"`
	// TrustStores this policy statement uses
	TrustStores []string `json:"trustStores,omitempty"`
	// TrustedIdentities this policy statement pins
	TrustedIdentities []string `json:"trustedIdentities,omitempty"`
}

// SignatureVerification represents verification configuration in a trust policy
type SignatureVerification struct {
	VerificationLevel string                              `json:"level"`
	Override          map[ValidationType]ValidationAction `json:"override,omitempty"`
}

// Validate validates a policy document according to it's version's rule set.
// if any rule is violated, returns an error
func (policyDoc *Document) Validate() error {
	// Constants
	supportedPolicyVersions := []string{"1.0"}

	// Validate Version
	if !common.IsPresent(policyDoc.Version, supportedPolicyVersions) {
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

		// Verify signature verification level is valid
		verificationLevel, err := GetVerificationLevel(statement.SignatureVerification)
		if err != nil {
			return fmt.Errorf("trust policy statement %q uses invalid signatureVerification value %q", statement.Name, statement.SignatureVerification.VerificationLevel)
		}

		// Any signature verification other than "skip" needs a trust store and trusted identities
		if verificationLevel.Name == "skip" {
			if len(statement.TrustStores) > 0 || len(statement.TrustedIdentities) > 0 {
				return fmt.Errorf("trust policy statement %q is set to skip signature verification but configured with trust stores and/or trusted identities, remove them if signature verification needs to be skipped", statement.Name)
			}
		} else {
			if len(statement.TrustStores) == 0 || len(statement.TrustedIdentities) == 0 {
				return fmt.Errorf("trust policy statement %q is either missing trust stores or trusted identities, both must be specified", statement.Name)
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

// GetVerificationLevel returns VerificationLevel struct for the given SignatureVerification struct
// throws error if SignatureVerification is invalid
func GetVerificationLevel(signatureVerification SignatureVerification) (*VerificationLevel, error) {
	var baseLevel *VerificationLevel
	for _, l := range VerificationLevels {
		if l.Name == signatureVerification.VerificationLevel {
			baseLevel = l
		}
	}
	if baseLevel == nil {
		return nil, fmt.Errorf("invalid signature verification %q", signatureVerification.VerificationLevel)
	}

	if len(signatureVerification.Override) == 0 {
		// nothing to override, return the base verification level
		return baseLevel, nil
	}

	if baseLevel == LevelSkip {
		return nil, fmt.Errorf("signature verification %q can't be used to customize signature verification", baseLevel.Name)
	}

	customVerificationLevel := &VerificationLevel{
		Name:        "custom",
		Enforcement: make(map[ValidationType]ValidationAction),
	}

	// populate the custom verification level with the base verification settings
	for k, v := range baseLevel.Enforcement {
		customVerificationLevel.Enforcement[k] = v
	}

	// override the verification actions with the user configured settings
	for key, value := range signatureVerification.Override {
		var validationType ValidationType
		for _, t := range ValidationTypes {
			if t == key {
				validationType = t
				break
			}
		}
		if validationType == "" {
			return nil, fmt.Errorf("verification type %q in custom signature verification is not supported, supported values are %q", key, ValidationTypes)
		}

		var validationAction ValidationAction
		for _, action := range ValidationActions {
			if action == value {
				validationAction = action
				break
			}
		}
		if validationAction == "" {
			return nil, fmt.Errorf("verification action %q in custom signature verification is not supported, supported values are %q", value, ValidationActions)
		}

		if validationType == TypeIntegrity {
			return nil, fmt.Errorf("%q verification can not be overridden in custom signature verification", key)
		} else if validationType != TypeRevocation && validationAction == ActionSkip {
			return nil, fmt.Errorf("%q verification can not be skipped in custom signature verification", key)
		}

		customVerificationLevel.Enforcement[validationType] = validationAction
	}
	return customVerificationLevel, nil
}

// validateTrustStore validates if the policy statement is following the Notary V2 spec rules for truststores
func validateTrustStore(statement TrustPolicy) error {
	for _, trustStore := range statement.TrustStores {
		i := strings.Index(trustStore, ":")
		if i < 0 || !isValidTrustStoreType(trustStore[:i]) {
			return fmt.Errorf("trust policy statement %q uses an unsupported trust store type %q in trust store value %q", statement.Name, trustStore[:i], trustStore)
		}
	}

	return nil
}

// validateTrustedIdentities validates if the policy statement is following the Notary V2 spec rules for trusted identities
func validateTrustedIdentities(statement TrustPolicy) error {

	// If there is a wildcard in trusted identies, there shouldn't be any other identities
	if len(statement.TrustedIdentities) > 1 && common.IsPresent(common.Wildcard, statement.TrustedIdentities) {
		return fmt.Errorf("trust policy statement %q uses a wildcard trusted identity '*', a wildcard identity cannot be used in conjunction with other values", statement.Name)
	}

	var parsedDNs []common.ParsedDN
	// If there are trusted identities, verify they are valid
	for _, identity := range statement.TrustedIdentities {
		if identity == "" {
			return fmt.Errorf("trust policy statement %q has an empty trusted identity", statement.Name)
		}

		if identity != common.Wildcard {
			i := strings.Index(identity, ":")
			if i < 0 {
				return fmt.Errorf("trust policy statement %q has trusted identity %q without an identity prefix", statement.Name, identity)
			}

			identityPrefix := identity[:i]
			identityValue := identity[i+1:]

			// notation natively supports x509.subject identities only
			if identityPrefix == common.X509Subject {
				dn, err := common.ParseDistinguishedName(identityValue)
				if err != nil {
					return err
				}
				parsedDNs = append(parsedDNs, common.ParsedDN{RawString: identity, ParsedMap: dn})
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

// validateRegistryScopes validates if the policy document is following the Notary V2 spec rules for registry scopes
func validateRegistryScopes(policyDoc *Document) error {
	registryScopeCount := make(map[string]int)

	for _, statement := range policyDoc.TrustPolicies {
		// Verify registry scopes are valid
		if len(statement.RegistryScopes) == 0 {
			return fmt.Errorf("trust policy statement %q has zero registry scopes, it must specify registry scopes with at least one value", statement.Name)
		}
		if len(statement.RegistryScopes) > 1 && common.IsPresent(common.Wildcard, statement.RegistryScopes) {
			return fmt.Errorf("trust policy statement %q uses wildcard registry scope '*', a wildcard scope cannot be used in conjunction with other scope values", statement.Name)
		}
		for _, scope := range statement.RegistryScopes {
			if scope != common.Wildcard {
				if err := common.ValidateRegistryScopeFormat(scope); err != nil {
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

func validateOverlappingDNs(policyName string, parsedDNs []common.ParsedDN) error {
	for i, dn1 := range parsedDNs {
		for j, dn2 := range parsedDNs {
			if i != j && common.IsSubsetDN(dn1.ParsedMap, dn2.ParsedMap) {
				return fmt.Errorf("trust policy statement %q has overlapping x509 trustedIdentities, %q overlaps with %q", policyName, dn1.RawString, dn2.RawString)
			}
		}
	}

	return nil
}

// isValidTrustStoreType returns true if the given string is a valid truststore.Type, otherwise false.
func isValidTrustStoreType(s string) bool {
	for _, p := range truststore.Types {
		if s == string(p) {
			return true
		}
	}
	return false
}
