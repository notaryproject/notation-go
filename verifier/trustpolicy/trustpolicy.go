// Package trustpolicy provides functionalities for trust policy document
// and trust policy statements.
package trustpolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/internal/file"
	"github.com/notaryproject/notation-go/internal/pkix"
	"github.com/notaryproject/notation-go/internal/slices"
	"github.com/notaryproject/notation-go/internal/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
)

// trustPolicyLink is a tutorial link for creating Notation's trust policy.
const trustPolicyLink = "https://notaryproject.dev/docs/quickstart/#create-a-trust-policy"

// ValidationType is an enum for signature verification types such as Integrity,
// Authenticity, etc.
type ValidationType string

// ValidationAction is an enum for signature verification actions such as
// Enforced, Logged, Skipped.
type ValidationAction string

// VerificationLevel encapsulates the signature verification preset and its
// actions for each verification type
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
)

const (
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
)

var (
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

var supportedPolicyVersions = []string{"1.0"}

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

// Validate validates a policy document according to its version's rule set.
// if any rule is violated, returns an error
func (policyDoc *Document) Validate() error {
	// sanity check
	if policyDoc == nil {
		return errors.New("trust policy document cannot be nil")
	}

	// Validate Version
	if policyDoc.Version == "" {
		return errors.New("trust policy document is missing or has empty version, it must be specified")
	}
	if !slices.Contains(supportedPolicyVersions, policyDoc.Version) {
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

		// Verify signature verification is valid
		verificationLevel, err := statement.SignatureVerification.GetVerificationLevel()
		if err != nil {
			return fmt.Errorf("trust policy statement %q has invalid signatureVerification: %w", statement.Name, err)
		}

		// Any signature verification other than "skip" needs a trust store and
		// trusted identities
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

// GetApplicableTrustPolicy returns a pointer to the deep copied TrustPolicy
// statement that applies to the given registry scope. If no applicable trust
// policy is found, returns an error
// see https://github.com/notaryproject/notaryproject/blob/v1.0.0-rc.2/specs/trust-store-trust-policy.md#selecting-a-trust-policy-based-on-artifact-uri
func (trustPolicyDoc *Document) GetApplicableTrustPolicy(artifactReference string) (*TrustPolicy, error) {
	artifactPath, err := getArtifactPathFromReference(artifactReference)
	if err != nil {
		return nil, err
	}

	var wildcardPolicy *TrustPolicy
	var applicablePolicy *TrustPolicy
	for _, policyStatement := range trustPolicyDoc.TrustPolicies {
		if slices.Contains(policyStatement.RegistryScopes, trustpolicy.Wildcard) {
			// we need to deep copy because we can't use the loop variable
			// address. see https://stackoverflow.com/a/45967429
			wildcardPolicy = (&policyStatement).clone()
		} else if slices.Contains(policyStatement.RegistryScopes, artifactPath) {
			applicablePolicy = (&policyStatement).clone()
		}
	}

	if applicablePolicy != nil {
		// a policy with exact match for registry scope takes precedence over
		// a wildcard (*) policy.
		return applicablePolicy, nil
	} else if wildcardPolicy != nil {
		return wildcardPolicy, nil
	} else {
		return nil, fmt.Errorf("artifact %q has no applicable trust policy. Trust policy applicability for a given artifact is determined by registryScopes. How to set up Notation trust policy: %s", artifactReference, trustPolicyLink)
	}
}

// LoadDocument loads a trust policy document from a local file system
func LoadDocument() (*Document, error) {
	jsonFile, err := dir.ConfigFS().Open(dir.PathTrustPolicy)
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			return nil, fmt.Errorf("trust policy is not present, please create trust policy at %s. How to set up Notation trust policy: %s", filepath.Join(dir.UserConfigDir, dir.PathTrustPolicy), trustPolicyLink)
		case errors.Is(err, os.ErrPermission):
			return nil, fmt.Errorf("unable to read trust policy due to file permissions, please verify the permissions of %s", filepath.Join(dir.UserConfigDir, dir.PathTrustPolicy))
		default:
			return nil, err
		}
	}
	defer jsonFile.Close()
	policyDocument := &Document{}
	err = json.NewDecoder(jsonFile).Decode(policyDocument)
	if err != nil {
		return nil, fmt.Errorf("malformed trustpolicy.json file. How to set up Notation trust policy: %s", trustPolicyLink)
	}
	return policyDocument, nil
}

// GetVerificationLevel returns VerificationLevel struct for the given
// SignatureVerification struct throws error if SignatureVerification is invalid
func (signatureVerification *SignatureVerification) GetVerificationLevel() (*VerificationLevel, error) {
	if signatureVerification.VerificationLevel == "" {
		return nil, errors.New("signature verification level is empty or missing in the trust policy statement")
	}

	var baseLevel *VerificationLevel
	for _, l := range VerificationLevels {
		if l.Name == signatureVerification.VerificationLevel {
			baseLevel = l
		}
	}
	if baseLevel == nil {
		return nil, fmt.Errorf("invalid signature verification level %q", signatureVerification.VerificationLevel)
	}

	if len(signatureVerification.Override) == 0 {
		// nothing to override, return the base verification level
		return baseLevel, nil
	}

	if baseLevel == LevelSkip {
		return nil, fmt.Errorf("signature verification level %q can't be used to customize signature verification", baseLevel.Name)
	}

	customVerificationLevel := &VerificationLevel{
		Name:        "custom",
		Enforcement: make(map[ValidationType]ValidationAction),
	}

	// populate the custom verification level with the base verification
	// settings
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

// clone returns a pointer to the deeply copied TrustPolicy
func (t *TrustPolicy) clone() *TrustPolicy {
	return &TrustPolicy{
		Name:                  t.Name,
		SignatureVerification: t.SignatureVerification,
		RegistryScopes:        append([]string(nil), t.RegistryScopes...),
		TrustedIdentities:     append([]string(nil), t.TrustedIdentities...),
		TrustStores:           append([]string(nil), t.TrustStores...),
	}
}

// validateTrustStore validates if the policy statement is following the
// Notation spec rules for truststores
func validateTrustStore(statement TrustPolicy) error {
	for _, trustStore := range statement.TrustStores {
		storeType, namedStore, found := strings.Cut(trustStore, ":")
		if !found {
			return fmt.Errorf("trust policy statement %q has malformed trust store value %q. The required format is <TrustStoreType>:<TrustStoreName>", statement.Name, trustStore)
		}
		if !isValidTrustStoreType(storeType) {
			return fmt.Errorf("trust policy statement %q uses an unsupported trust store type %q in trust store value %q", statement.Name, storeType, trustStore)
		}
		if !file.IsValidFileName(namedStore) {
			return fmt.Errorf("trust policy statement %q uses an unsupported trust store name %q in trust store value %q. Named store name needs to follow [a-zA-Z0-9_.-]+ format", statement.Name, namedStore, trustStore)
		}
	}

	return nil
}

// validateTrustedIdentities validates if the policy statement is following the
// Notation spec rules for trusted identities
func validateTrustedIdentities(statement TrustPolicy) error {
	// If there is a wildcard in trusted identies, there shouldn't be any other
	//identities
	if len(statement.TrustedIdentities) > 1 && slices.Contains(statement.TrustedIdentities, trustpolicy.Wildcard) {
		return fmt.Errorf("trust policy statement %q uses a wildcard trusted identity '*', a wildcard identity cannot be used in conjunction with other values", statement.Name)
	}

	var parsedDNs []parsedDN
	// If there are trusted identities, verify they are valid
	for _, identity := range statement.TrustedIdentities {
		if identity == "" {
			return fmt.Errorf("trust policy statement %q has an empty trusted identity", statement.Name)
		}

		if identity != trustpolicy.Wildcard {
			identityPrefix, identityValue, found := strings.Cut(identity, ":")
			if !found {
				return fmt.Errorf("trust policy statement %q has trusted identity %q missing separator", statement.Name, identity)
			}

			// notation natively supports x509.subject identities only
			if identityPrefix == trustpolicy.X509Subject {
				// identityValue cannot be empty
				if identityValue == "" {
					return fmt.Errorf("trust policy statement %q has trusted identity %q without an identity value", statement.Name, identity)
				}
				dn, err := pkix.ParseDistinguishedName(identityValue)
				if err != nil {
					return err
				}
				parsedDNs = append(parsedDNs, parsedDN{RawString: identity, ParsedMap: dn})
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

// validateRegistryScopes validates if the policy document is following the
// Notation spec rules for registry scopes
func validateRegistryScopes(policyDoc *Document) error {
	registryScopeCount := make(map[string]int)
	for _, statement := range policyDoc.TrustPolicies {
		// Verify registry scopes are valid
		if len(statement.RegistryScopes) == 0 {
			return fmt.Errorf("trust policy statement %q has zero registry scopes, it must specify registry scopes with at least one value", statement.Name)
		}
		if len(statement.RegistryScopes) > 1 && slices.Contains(statement.RegistryScopes, trustpolicy.Wildcard) {
			return fmt.Errorf("trust policy statement %q uses wildcard registry scope '*', a wildcard scope cannot be used in conjunction with other scope values", statement.Name)
		}
		for _, scope := range statement.RegistryScopes {
			if scope != trustpolicy.Wildcard {
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

func validateOverlappingDNs(policyName string, parsedDNs []parsedDN) error {
	for i, dn1 := range parsedDNs {
		for j, dn2 := range parsedDNs {
			if i != j && pkix.IsSubsetDN(dn1.ParsedMap, dn2.ParsedMap) {
				return fmt.Errorf("trust policy statement %q has overlapping x509 trustedIdentities, %q overlaps with %q", policyName, dn1.RawString, dn2.RawString)
			}
		}
	}

	return nil
}

// isValidTrustStoreType returns true if the given string is a valid
// truststore.Type, otherwise false.
func isValidTrustStoreType(s string) bool {
	for _, p := range truststore.Types {
		if s == string(p) {
			return true
		}
	}
	return false
}

func getArtifactPathFromReference(artifactReference string) (string, error) {
	// TODO support more types of URI like "domain.com/repository",
	// "domain.com/repository:tag"
	i := strings.LastIndex(artifactReference, "@")
	if i < 0 {
		return "", fmt.Errorf("artifact URI %q could not be parsed, make sure it is the fully qualified OCI artifact URI without the scheme/protocol. e.g domain.com:80/my/repository@sha256:digest", artifactReference)
	}

	artifactPath := artifactReference[:i]
	if err := validateRegistryScopeFormat(artifactPath); err != nil {
		return "", err
	}
	return artifactPath, nil
}

// Internal type to hold raw and parsed Distinguished Names
type parsedDN struct {
	RawString string
	ParsedMap map[string]string
}

// validateRegistryScopeFormat validates if a scope is following the format
// defined in distribution spec
func validateRegistryScopeFormat(scope string) error {
	// Domain and Repository regexes are adapted from distribution
	// implementation
	// https://github.com/distribution/distribution/blob/main/reference/regexp.go#L31
	domainRegexp := regexp.MustCompile(`^(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])(?:(?:\.(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]))+)?(?::[0-9]+)?$`)
	repositoryRegexp := regexp.MustCompile(`^[a-z0-9]+(?:(?:(?:[._]|__|[-]*)[a-z0-9]+)+)?(?:(?:/[a-z0-9]+(?:(?:(?:[._]|__|[-]*)[a-z0-9]+)+)?)+)?$`)
	errorMessage := "registry scope %q is not valid, make sure it is a fully qualified registry URL without the scheme/protocol, e.g domain.com/my/repository OR a local trust policy scope, e.g local/myOCILayout"
	domain, repository, found := strings.Cut(scope, "/")
	if !found {
		return fmt.Errorf(errorMessage, scope)
	}

	if domain == "" || repository == "" || !domainRegexp.MatchString(domain) || !repositoryRegexp.MatchString(repository) {
		return fmt.Errorf(errorMessage, scope)
	}

	// No errors
	return nil
}
