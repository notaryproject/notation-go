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

	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/internal/slices"
)

// BlobDocument represents a trustpolicy.blob.json document
type BlobDocument struct {
	// Version of the policy document
	Version string `json:"version"`

	// BlobTrustPolicies include each policy statement
	BlobTrustPolicies []BlobTrustPolicy `json:"trustPolicies"`
}

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

// LoadBlobDocument loads a trust policy document from a local file system
func LoadBlobDocument() (*BlobDocument, error) {
	var doc BlobDocument
	err := getDocument(dir.PathBlobTrustPolicy, &doc)
	return &doc, err
}

// Validate validates a policy document according to its version's rule set.
// if any rule is violated, returns an error
func (policyDoc *BlobDocument) Validate() error {
	// sanity check
	if policyDoc == nil {
		return errors.New("blob trust policy document cannot be nil")
	}

	// Validate Version
	if policyDoc.Version == "" {
		return errors.New("blob trust policy has empty version, version must be specified")
	}
	if !slices.Contains(supportedPolicyVersions, policyDoc.Version) {
		return fmt.Errorf("blob trust policy document uses unsupported version %q", policyDoc.Version)
	}

	// Validate the policy according to 1.0 rules
	if len(policyDoc.BlobTrustPolicies) == 0 {
		return errors.New("blob trust policy document can not have zero trust policy statements")
	}

	policyStatementNameCount := make(map[string]int)
	foundGlobalPolicy := false
	for _, statement := range policyDoc.BlobTrustPolicies {
		policyStatementNameCount[statement.Name]++
		if err := validatePolicyCore(statement.Name, statement.SignatureVerification, statement.TrustStores, statement.TrustedIdentities); err != nil {
			return err
		}

		if statement.GlobalPolicy {
			if foundGlobalPolicy {
				return errors.New("multiple blob trust policy statements have globalPolicy set to true. Only one trust policy statement should be marked as global policy")
			}
			foundGlobalPolicy = true
		}
	}

	// Verify unique policy statement names across the policy document
	for key := range policyStatementNameCount {
		if policyStatementNameCount[key] > 1 {
			return fmt.Errorf("multiple blob trust policy statements use the same name %q, statement names must be unique", key)
		}
	}

	return nil
}

// GetApplicableTrustPolicy returns a pointer to the deep copied TrustPolicy
// statement that applies to the given registry scope. If no applicable trust
// policy is found, returns an error
// see https://github.com/notaryproject/notaryproject/blob/v1.0.0-rc.2/specs/trust-store-trust-policy.md#selecting-a-trust-policy-based-on-artifact-uri
func (policyDoc *BlobDocument) GetApplicableTrustPolicy(policyName string) (*BlobTrustPolicy, error) {
	for _, policyStatement := range policyDoc.BlobTrustPolicies {
		if policyName == "" {
			// global policy
			if policyStatement.GlobalPolicy {
				return (&policyStatement).clone(), nil
			}
		} else {
			// exact match
			if policyStatement.Name == policyName {
				return (&policyStatement).clone(), nil
			}
		}
	}

	return nil, fmt.Errorf("no applicable blob trust policy. Applicability for a given blob is determined by policy name")
}

// clone returns a pointer to the deeply copied TrustPolicy
func (t *BlobTrustPolicy) clone() *BlobTrustPolicy {
	return &BlobTrustPolicy{
		Name:                  t.Name,
		SignatureVerification: t.SignatureVerification,
		TrustedIdentities:     append([]string(nil), t.TrustedIdentities...),
		TrustStores:           append([]string(nil), t.TrustStores...),
		GlobalPolicy:          t.GlobalPolicy,
	}
}
