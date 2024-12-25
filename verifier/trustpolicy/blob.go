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

package trustpolicy

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/notaryproject/notation-go/dir"
	set "github.com/notaryproject/notation-go/internal/container"
	"github.com/notaryproject/notation-go/internal/slices"
)

// BlobDocument represents a trustpolicy.blob.json document for arbitrary blobs
type BlobDocument struct {
	// Version of the policy document
	Version string `json:"version"`

	// TrustPolicies include each policy statement
	TrustPolicies []BlobTrustPolicy `json:"trustPolicies"`
}

// BlobTrustPolicy represents a policy statement in the blob trust policy
// document
type BlobTrustPolicy struct {
	// Name of the policy statement
	Name string `json:"name"`

	// SignatureVerification setting for this policy statement
	SignatureVerification SignatureVerification `json:"signatureVerification"`

	// TrustStores this policy statement uses
	TrustStores []string `json:"trustStores"`

	// TrustedIdentities this policy statement pins
	TrustedIdentities []string `json:"trustedIdentities"`

	// GlobalPolicy defines if policy statement is global or not
	GlobalPolicy bool `json:"globalPolicy,omitempty"`
}

var supportedBlobPolicyVersions = []string{"1.0"}

// LoadBlobDocument loads a blob trust policy document from a local file system
func LoadBlobDocument() (*BlobDocument, error) {
	var doc BlobDocument
	err := getDocument(dir.PathBlobTrustPolicy, &doc)
	return &doc, err
}

// Validate validates a blob trust policy document according to its version's
// rule set.
// If any rule is violated, returns an error
func (policyDoc *BlobDocument) Validate() error {
	// sanity check
	if policyDoc == nil {
		return errors.New("blob trust policy document cannot be nil")
	}

	// Validate Version
	if policyDoc.Version == "" {
		return errors.New("blob trust policy has empty version, version must be specified")
	}
	if !slices.Contains(supportedBlobPolicyVersions, policyDoc.Version) {
		return fmt.Errorf("blob trust policy document uses unsupported version %q", policyDoc.Version)
	}

	// Validate the policy according to 1.0 rules
	if len(policyDoc.TrustPolicies) == 0 {
		return errors.New("blob trust policy document can not have zero trust policy statements")
	}

	policyNames := set.New[string]()
	var foundGlobalPolicy bool
	for _, statement := range policyDoc.TrustPolicies {
		// Verify unique policy statement names across the policy document
		if policyNames.Contains(statement.Name) {
			return fmt.Errorf("multiple blob trust policy statements use the same name %q, statement names must be unique", statement.Name)
		}

		if err := validatePolicyCore(statement.Name, statement.SignatureVerification, statement.TrustStores, statement.TrustedIdentities); err != nil {
			return fmt.Errorf("blob trust policy: %w", err)
		}

		if statement.GlobalPolicy {
			if foundGlobalPolicy {
				return errors.New("multiple blob trust policy statements have globalPolicy set to true. Only one trust policy statement can be marked as global policy")
			}

			// verificationLevel is skip
			if reflect.DeepEqual(statement.SignatureVerification.VerificationLevel, LevelSkip) {
				return errors.New("global blob trust policy statement cannot have verification level set to skip")
			}

			foundGlobalPolicy = true
		}
		policyNames.Add(statement.Name)
	}

	return nil
}

// GetApplicableTrustPolicy returns a pointer to the deep copied [BlobTrustPolicy]
// for given policy name.
// see https://github.com/notaryproject/notaryproject/blob/v1.1.0/specs/trust-store-trust-policy.md#blob-trust-policy
func (policyDoc *BlobDocument) GetApplicableTrustPolicy(policyName string) (*BlobTrustPolicy, error) {
	if strings.TrimSpace(policyName) == "" {
		return nil, errors.New("policy name cannot be empty")
	}
	for _, policyStatement := range policyDoc.TrustPolicies {
		// exact match
		if policyStatement.Name == policyName {
			return (&policyStatement).clone(), nil
		}
	}

	return nil, fmt.Errorf("no applicable blob trust policy with name %q", policyName)
}

// GetGlobalTrustPolicy returns a pointer to the deep copied [BlobTrustPolicy]
// that is marked as global policy.
// see https://github.com/notaryproject/notaryproject/blob/v1.1.0/specs/trust-store-trust-policy.md#blob-trust-policy
func (policyDoc *BlobDocument) GetGlobalTrustPolicy() (*BlobTrustPolicy, error) {
	for _, policyStatement := range policyDoc.TrustPolicies {
		if policyStatement.GlobalPolicy {
			return (&policyStatement).clone(), nil
		}
	}

	return nil, fmt.Errorf("no global blob trust policy")
}

// clone returns a pointer to the deep copied [BlobTrustPolicy]
func (t *BlobTrustPolicy) clone() *BlobTrustPolicy {
	return &BlobTrustPolicy{
		Name:                  t.Name,
		SignatureVerification: t.SignatureVerification,
		TrustedIdentities:     append([]string(nil), t.TrustedIdentities...),
		TrustStores:           append([]string(nil), t.TrustStores...),
		GlobalPolicy:          t.GlobalPolicy,
	}
}
