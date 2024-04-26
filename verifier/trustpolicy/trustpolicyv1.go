// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package trustpolicy provides functionalities for trust policy document
// and trust policy statements.
package trustpolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

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
	commonPolicy, err := policyDoc.ToTrustPolicyDocument()
	if err != nil {
		return err
	}
	return commonPolicy.Validate()
}

// GetApplicableTrustPolicy returns a pointer to the deep copied TrustPolicy
// statement that applies to the given registry scope. If no applicable trust
// policy is found, returns an error
// see https://github.com/notaryproject/notaryproject/blob/v1.0.0-rc.2/specs/trust-store-trust-policy.md#selecting-a-trust-policy-based-on-artifact-uri
func (trustPolicyDoc *Document) GetApplicableTrustPolicy(artifactReference string) (*TrustPolicy, error) {
	artifactPath, err := trustpolicy.GetArtifactPathFromReference(artifactReference)
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
		return nil, fmt.Errorf("artifact %q has no applicable trust policy. Trust policy applicability for a given artifact is determined by registryScopes. To create a trust policy, see: %s", artifactReference, trustPolicyLink)
	}
}

// ToTrustPolicyDocument converts the trust policy v1.0 to be trust policy
// common model.
func (trustpolicyDoc *Document) ToTrustPolicyDocument() (*trustpolicy.Document, error) {
	policies := make([]trustpolicy.TrustPolicy, len(trustpolicyDoc.TrustPolicies))
	for i, policy := range trustpolicyDoc.TrustPolicies {
		// convert the signature verification
		var signatureVerification trustpolicy.SignatureVerification
		signatureVerification.VerificationLevel = policy.SignatureVerification.VerificationLevel
		signatureVerification.Override = make(map[trustpolicy.ValidationType]trustpolicy.ValidationAction)
		for k, v := range policy.SignatureVerification.Override {
			signatureVerification.Override[trustpolicy.ValidationType(k)] = trustpolicy.ValidationAction(v)
		}

		// convert the trust store
		var trustStores trustpolicy.TrustStores
		for _, store := range policy.TrustStores {
			storeType, namedStore, found := strings.Cut(store, ":")
			if !found {
				return nil, fmt.Errorf("trust policy statement %q has malformed trust store value %q. The required format is <TrustStoreType>:<TrustStoreName>", policy.Name, store)
			}
			switch storeType {
			case string(truststore.TypeCA):
				trustStores.CA = append(trustStores.CA, namedStore)
			case string(truststore.TypeSigningAuthority):
				trustStores.SigningAuthority = append(trustStores.SigningAuthority, namedStore)
			default:
				return nil, fmt.Errorf("trust policy statement %q uses an unsupported trust store type %q in trust store value %q", policy.Name, storeType, store)
			}
		}

		// convert the trusted identities
		var trustedIdentities trustpolicy.TrustIdentities
		for _, identity := range policy.TrustedIdentities {
			trustedIdentities.CA = append(trustedIdentities.CA, identity)
			trustedIdentities.SigningAuthority = append(trustedIdentities.SigningAuthority, identity)
		}

		policies[i] = trustpolicy.TrustPolicy{
			Name:                  policy.Name,
			RegistryScopes:        policy.RegistryScopes,
			SignatureVerification: signatureVerification,
			TrustStores:           trustStores,
			TrustedIdentities:     trustedIdentities,
		}
	}
	return &trustpolicy.Document{
		Version:       trustpolicyDoc.Version,
		TrustPolicies: policies,
	}, nil
}

// LoadDocument loads a trust policy document v1.0 from a local file system
func LoadDocument() (*Document, error) {
	jsonFile, err := openTrustPlicy()
	if err != nil {
		return nil, err
	}
	defer jsonFile.Close()

	policyDocument := &Document{}
	err = json.NewDecoder(jsonFile).Decode(policyDocument)
	if err != nil {
		return nil, fmt.Errorf("malformed trust policy. To create a trust policy, see: %s", trustPolicyLink)
	}
	return policyDocument, nil
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
