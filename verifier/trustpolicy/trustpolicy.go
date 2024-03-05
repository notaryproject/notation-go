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
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/internal/file"
	"github.com/notaryproject/notation-go/internal/pkix"
	"github.com/notaryproject/notation-go/internal/slices"
	"github.com/notaryproject/notation-go/internal/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
)

type Type int

const (
	TypeBlob Type = iota + 1
	TypeOCI
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

// SignatureVerification represents verification configuration in a trust policy
type SignatureVerification struct {
	VerificationLevel string                              `json:"level"`
	Override          map[ValidationType]ValidationAction `json:"override,omitempty"`
}

func Get(p Type) (interface{}, error) {
	switch p {
	case TypeBlob:
		return loadBlobDocument()
	case TypeOCI:
		return loadBlobDocument()
	}
	return 0, fmt.Errorf("invalid policy type:L %v", p)
}

func getDocument(path string, v any) error {
	path, err := dir.ConfigFS().SysPath(path)
	if err != nil {
		return err
	}

	// throw error if path is a directory or a symlink or does not exist.
	fileInfo, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("trust policy is not present. To create a trust policy, see: %s", trustPolicyLink)
		}
		return err
	}

	mode := fileInfo.Mode()
	if mode.IsDir() || mode&fs.ModeSymlink != 0 {
		return fmt.Errorf("trust policy is not a regular file (symlinks are not supported). To create a trust policy, see: %s", trustPolicyLink)
	}

	jsonFile, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("unable to read trust policy due to file permissions, please verify the permissions of %s", filepath.Join(dir.UserConfigDir, path))
		}
		return err
	}
	defer jsonFile.Close()

	err = json.NewDecoder(jsonFile).Decode(v)
	if err != nil {
		return fmt.Errorf("malformed trust policy. To create a trust policy, see: %s", trustPolicyLink)
	}
	return nil

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

func validateCore(name string, signatureVerification SignatureVerification, trustStores, trustedIdentities []string) error {
	// Verify statement name is valid
	if name == "" {
		return errors.New("a trust policy statement is missing a name, every statement requires a name")
	}

	// Verify signature verification is valid
	verificationLevel, err := signatureVerification.GetVerificationLevel()
	if err != nil {
		return fmt.Errorf("trust policy statement %q has invalid signatureVerification: %w", name, err)
	}

	// Any signature verification other than "skip" needs a trust store and
	// trusted identities
	if verificationLevel.Name == "skip" {
		if len(trustStores) > 0 || len(trustedIdentities) > 0 {
			return fmt.Errorf("trust policy statement %q is set to skip signature verification but configured with trust stores and/or trusted identities, remove them if signature verification needs to be skipped", name)
		}
	} else {
		if len(trustStores) == 0 || len(trustedIdentities) == 0 {
			return fmt.Errorf("trust policy statement %q is either missing trust stores or trusted identities, both must be specified", name)
		}

		// Verify Trust Store is valid
		if err := validateTrustStore(name, trustStores); err != nil {
			return err
		}

		// Verify Trusted Identities are valid
		if err := validateTrustedIdentities(name, trustedIdentities); err != nil {
			return err
		}
	}
	return nil
}

// validateTrustStore validates if the policy statement is following the
// Notary Project spec rules for truststore
func validateTrustStore(name string, trustStores []string) error {
	for _, trustStore := range trustStores {
		storeType, namedStore, found := strings.Cut(trustStore, ":")
		if !found {
			return fmt.Errorf("trust policy statement %q has malformed trust store value %q. The required format is <TrustStoreType>:<TrustStoreName>", name, trustStore)
		}
		if !isValidTrustStoreType(storeType) {
			return fmt.Errorf("trust policy statement %q uses an unsupported trust store type %q in trust store value %q", name, storeType, trustStore)
		}
		if !file.IsValidFileName(namedStore) {
			return fmt.Errorf("trust policy statement %q uses an unsupported trust store name %q in trust store value %q. Named store name needs to follow [a-zA-Z0-9_.-]+ format", name, namedStore, trustStore)
		}
	}

	return nil
}

// validateTrustedIdentities validates if the policy statement is following the
// Notary Project spec rules for trusted identities
func validateTrustedIdentities(name string, tis []string) error {
	// If there is a wildcard in trusted identities, there shouldn't be any other
	//identities
	if len(tis) > 1 && slices.Contains(tis, trustpolicy.Wildcard) {
		return fmt.Errorf("trust policy statement %q uses a wildcard trusted identity '*', a wildcard identity cannot be used in conjunction with other values", name)
	}

	var parsedDNs []parsedDN
	// If there are trusted identities, verify they are valid
	for _, identity := range tis {
		if identity == "" {
			return fmt.Errorf("trust policy statement %q has an empty trusted identity", name)
		}

		if identity != trustpolicy.Wildcard {
			identityPrefix, identityValue, found := strings.Cut(identity, ":")
			if !found {
				return fmt.Errorf("trust policy statement %q has trusted identity %q missing separator", name, identity)
			}

			// notation natively supports x509.subject identities only
			if identityPrefix == trustpolicy.X509Subject {
				// identityValue cannot be empty
				if identityValue == "" {
					return fmt.Errorf("trust policy statement %q has trusted identity %q without an identity value", name, identity)
				}
				dn, err := pkix.ParseDistinguishedName(identityValue)
				if err != nil {
					return fmt.Errorf("trust policy statement %q has trusted identity %q with invalid identity value: %w", name, identity, err)
				}
				parsedDNs = append(parsedDNs, parsedDN{RawString: identity, ParsedMap: dn})
			}
		}
	}

	// Verify there are no overlapping DNs
	if err := validateOverlappingDNs(name, parsedDNs); err != nil {
		return err
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

// Internal type to hold raw and parsed Distinguished Names
type parsedDN struct {
	RawString string
	ParsedMap map[string]string
}
