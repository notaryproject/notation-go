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
	"regexp"
	"strings"

	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/internal/slices"
	"github.com/notaryproject/notation-go/internal/trustpolicy"
)

// OCIDocument represents a trustPolicy.json document for OCI artifacts
type OCIDocument struct {
	// Version of the policy document
	Version string `json:"version"`

	// TrustPolicies include each policy statement
	TrustPolicies []OCITrustPolicy `json:"trustPolicies"`
}

// OCITrustPolicy represents a policy statement in the policy document for OCI artifacts
type OCITrustPolicy struct {
	// Name of the policy statement
	Name string `json:"name"`

	// SignatureVerification setting for this policy statement
	SignatureVerification SignatureVerification `json:"signatureVerification"`

	// TrustStores this policy statement uses
	TrustStores []string `json:"trustStores,omitempty"`

	// TrustedIdentities this policy statement pins
	TrustedIdentities []string `json:"trustedIdentities,omitempty"`

	// RegistryScopes that this policy statement affects
	RegistryScopes []string `json:"registryScopes"`
}

// Document represents a trustPolicy.json document
// Deprecated
type Document = OCIDocument

// TrustPolicy represents a policy statement in the policy document
// Deprecated
type TrustPolicy = OCITrustPolicy

// LoadDocument loads a trust policy document from a local file system
// Deprecated
var LoadDocument = LoadOCIDocument

// LoadOCIDocument loads a trust policy document from a local file system
func LoadOCIDocument() (*OCIDocument, error) {
	var doc OCIDocument
	err := getDocument(dir.PathOCITrustPolicy, &doc)
	return &doc, err
}

// Validate validates a policy document according to its version's rule set.
// if any rule is violated, returns an error
func (policyDoc *OCIDocument) Validate() error {
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
		if err := validateCore(statement.Name, statement.SignatureVerification, statement.TrustStores, statement.TrustedIdentities); err != nil {
			return err
		}
		policyStatementNameCount[statement.Name]++
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
func (policyDoc *OCIDocument) GetApplicableTrustPolicy(artifactReference string) (*OCITrustPolicy, error) {
	artifactPath, err := getArtifactPathFromReference(artifactReference)
	if err != nil {
		return nil, err
	}

	var wildcardPolicy *OCITrustPolicy
	var applicablePolicy *OCITrustPolicy
	for _, policyStatement := range policyDoc.TrustPolicies {
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

// clone returns a pointer to the deeply copied TrustPolicy
func (t *OCITrustPolicy) clone() *OCITrustPolicy {
	return &OCITrustPolicy{
		Name:                  t.Name,
		SignatureVerification: t.SignatureVerification,
		TrustedIdentities:     append([]string(nil), t.TrustedIdentities...),
		TrustStores:           append([]string(nil), t.TrustStores...),
		RegistryScopes:        append([]string(nil), t.RegistryScopes...),
	}
}

// validateRegistryScopes validates if the policy document is following the
// Notary Project spec rules for registry scopes
func validateRegistryScopes(policyDoc *OCIDocument) error {
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

// validateRegistryScopeFormat validates if a scope is following the format
// defined in distribution spec
func validateRegistryScopeFormat(scope string) error {
	// Domain and Repository regexes are adapted from distribution
	// implementation
	// https://github.com/distribution/distribution/blob/main/reference/regexp.go#L31
	domainRegexp := regexp.MustCompile(`^(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])(?:(?:\.(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]))+)?(?::[0-9]+)?$`)
	repositoryRegexp := regexp.MustCompile(`^[a-z0-9]+(?:(?:(?:[._]|__|[-]*)[a-z0-9]+)+)?(?:(?:/[a-z0-9]+(?:(?:(?:[._]|__|[-]*)[a-z0-9]+)+)?)+)?$`)
	ensureMessage := "make sure it is a fully qualified repository without the scheme, protocol or tag. For example domain.com/my/repository or a local scope like local/myOCILayout"
	errorMessage := "registry scope %q is not valid, " + ensureMessage
	errorWildCardMessage := "registry scope %q with wild card(s) is not valid, " + ensureMessage

	// Check for presence of * in scope
	if len(scope) > 1 && strings.Contains(scope, "*") {
		return fmt.Errorf(errorWildCardMessage, scope)
	}

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
