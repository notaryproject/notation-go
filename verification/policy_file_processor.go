package verification

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/notaryproject/notation-go/dir"
)

var (
	trustPolicyPath         string
	trustPolicyPathForWrite string
)

func init() {
	trustPolicyPath = dir.Path.TrustPolicy()
	trustPolicyPathForWrite = dir.Path.TrustPolicyForWrite(dir.UserLevel)
}

// PolicyDocumentOperation provides functions to manipulate TrustPolicies
// within a PolicyDocument.
type PolicyDocumentOperation interface {
	// AddPolicies adds given policies to the PolicyDocument.
	AddPolicies(policies []*TrustPolicy) error

	// GetPolicy returns the required policy.
	GetPolicy(policyName string) (*TrustPolicy, error)

	// ListPolicies lists all policies.
	ListPolicies() []*TrustPolicy

	// ListPoliciesWithinScope lists all policies under the given scope.
	ListPoliciesWithinScope(scope string) []*TrustPolicy

	// UpdatePolicies updates given policies within the PolicyDocument.
	UpdatePolicies(policies []*TrustPolicy) error

	// DeletePolicies deletes given policies from the PolicyDocument.
	DeletePolicies(names []string) error
}

// AddPolicies adds given policies to the PolicyDocument.
// It will not add any new policies if some policy fails to be added.
func (pd *PolicyDocument) AddPolicies(policies []*TrustPolicy) error {
	existingPolicies := pd.getNameToPolicyMap()

	for _, trustPolicy := range policies {
		if err := validatePolicy(trustPolicy); err != nil {
			return err
		}
		if _, exist := existingPolicies[trustPolicy.Name]; exist {
			return ErrorPolicyNameExists{
				Msg: fmt.Sprintf("%s already exists", trustPolicy.Name),
			}
		}
		existingPolicies[trustPolicy.Name] = trustPolicy
	}

	pd.overwritePolicies(existingPolicies)
	return pd.save()
}

// GetPolicy returns the policy of the specified name.
func (pd *PolicyDocument) GetPolicy(policyName string) (*TrustPolicy, error) {
	policies, err := pd.getPolicies([]string{policyName})
	if err != nil {
		return nil, err
	}
	if len(policies) == 0 {
		return nil, ErrorPolicyNotExists{
			Msg: fmt.Sprintf("%s not exists.", policyName),
		}
	}

	return policies[0], nil
}

// ListPolicies returns all policies defined in the PolicyDocument.
func (pd *PolicyDocument) ListPolicies() []*TrustPolicy {
	var policies []*TrustPolicy
	for _, policy := range pd.TrustPolicies {
		newPolicy := policy
		policies = append(policies, &newPolicy)
	}
	return policies
}

// ListPoliciesWithinScope returns all policies matching against the scope.
func (pd *PolicyDocument) ListPoliciesWithinScope(scope string) []*TrustPolicy {
	var filteredPolicies []*TrustPolicy
	policies := pd.ListPolicies()

	for _, policy := range policies {
		if isMatchedScope(policy.RegistryScopes, scope) {
			filteredPolicies = append(filteredPolicies, policy)
		}
	}

	return filteredPolicies
}

// isMatchedScope returns true if the given scope matches the scope list.
// A scope matches if either one holds true:
//   1. scopes contain global scope.
//   2. it's present in the scope list.
func isMatchedScope(scopes []string, matchingScope string) bool {
	if len(scopes) == 1 && scopes[0] == wildcard {
		return true
	}
	return isPresent(matchingScope, scopes)
}

// UpdatePolicy updates existing policy with given new policy.
// Notes: new policy only contains fields that need to be updated.
func (pd *PolicyDocument) UpdatePolicy(policy *TrustPolicy) error {
	existingPolicies := pd.getNameToPolicyMap()

	if _, exist := existingPolicies[policy.Name]; !exist {
		return ErrorPolicyNotExists{
			Msg: fmt.Sprintf("%s not exists.", policy.Name),
		}
	}
	mergedPolicy := mergePolicy(existingPolicies[policy.Name], policy)

	return pd.updatePolicies([]*TrustPolicy{mergedPolicy})
}

// UpdatePolicies updates existing policies with given new policies.
// Notes: new policies only contain fields that need to be updated.
func (pd *PolicyDocument) UpdatePolicies(policies []*TrustPolicy) error {
	existingPolicies := pd.getNameToPolicyMap()

	for idx, policy := range policies {
		if _, exist := existingPolicies[policy.Name]; !exist {
			return ErrorPolicyNotExists{
				Msg: fmt.Sprintf("%s not exists.", policy.Name),
			}
		}
		policies[idx] = mergePolicy(existingPolicies[policy.Name], policy)
	}

	return pd.updatePolicies(policies)
}

// updatePolicies updates existing policies by replacing them with given
// policies of the same name.
func (pd *PolicyDocument) updatePolicies(policies []*TrustPolicy) error {
	existingPolicies := pd.getNameToPolicyMap()

	for _, policy := range policies {
		if err := validatePolicy(policy); err != nil {
			return err
		}
		existingPolicies[policy.Name] = policy
	}

	pd.overwritePolicies(existingPolicies)
	return pd.save()
}

// DeletePolicies deletes specified policies from the PolicyDocument.
func (pd *PolicyDocument) DeletePolicies(names []string) error {
	existingPolicies := pd.getNameToPolicyMap()
	uniqueNames := make(map[string]struct{})
	for _, name := range names {
		uniqueNames[name] = struct{}{}
	}

	for name, _ := range uniqueNames {
		if _, exist := existingPolicies[name]; !exist {
			return ErrorPolicyNotExists{
				Msg: fmt.Sprintf("Policy %s does not exist", name),
			}
		}
		delete(existingPolicies, name)
	}
	// return error if all policies are deleted.
	if len(existingPolicies) == 0 {
		return errors.New("illegal to delete all policies")
	}

	pd.overwritePolicies(existingPolicies)
	return pd.save()
}

// getPolicies returns required policies by names.
func (pd *PolicyDocument) getPolicies(names []string) ([]*TrustPolicy, error) {
	existingPolicies := pd.getNameToPolicyMap()
	var policies []*TrustPolicy

	for _, name := range names {
		if _, ok := existingPolicies[name]; !ok {
			return nil, ErrorPolicyNotExists{
				Msg: fmt.Sprintf("%s not exists.", name),
			}
		}
		policies = append(policies, existingPolicies[name])
	}

	return policies, nil
}

// LoadDefaultPolicyDocument creates a PolicyDocument from default TrustPolicy
// file.
func LoadDefaultPolicyDocument() (*PolicyDocument, error) {
	policyDocument := &PolicyDocument{}
	jsonFile, err := os.Open(trustPolicyPath)
	if err != nil {
		return nil, err
	}
	defer jsonFile.Close()
	err = json.NewDecoder(jsonFile).Decode(policyDocument)
	if err != nil {
		return nil, err
	}
	return policyDocument, nil
}

// save stores the trust policy to file.
// TODO: move to config submodule.
func (c *PolicyDocument) save() error {
	dir := filepath.Dir(trustPolicyPathForWrite)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	file, err := os.Create(trustPolicyPathForWrite)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")
	return encoder.Encode(c)
}

func (pd *PolicyDocument) getNameToPolicyMap() map[string]*TrustPolicy {
	policies := make(map[string]*TrustPolicy)
	for _, policy := range pd.TrustPolicies {
		newPolicy := policy
		policies[policy.Name] = &newPolicy
	}
	return policies
}

// overwritePolicies replaces TrustPolicies of PolicyDocument with the given
// policies.
func (pd *PolicyDocument) overwritePolicies(newPolicies map[string]*TrustPolicy) {
	policies := make([]TrustPolicy, 0, len(newPolicies))
	for _, policy := range newPolicies {
		policies = append(policies, *policy)
	}
	pd.TrustPolicies = policies
}

// NewTrustPolicy creates a new TrustPolicy with speicified fields.
func NewTrustPolicy(name string, scopes []string, level string, override map[string]string, stores []string, identities []string) *TrustPolicy {
	return &TrustPolicy{
		Name:           name,
		RegistryScopes: scopes,
		SignatureVerification: SignatureVerification{
			Level:    level,
			Override: override,
		},
		TrustStores:       stores,
		TrustedIdentities: identities,
	}
}

// LoadTrustPolicies loads policies from the given file.
func LoadTrustPolicies(policyPath string) ([]*TrustPolicy, error) {
	policyBytes, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, err
	}
	policyBytes = bytes.Trim(policyBytes, " ")

	version, err := extractPolicyVersion(policyBytes)
	if err != nil {
		return nil, err
	}

	return ParseTrustPolicies(policyBytes, version)
}

// extractPolicyVersion extracts version by parsing the policy bytes.
func extractPolicyVersion(policyBytes []byte) (string, error) {
	var policy map[string]interface{}
	if err := json.Unmarshal(policyBytes, &policy); err != nil {
		return "", err
	}
	version, ok := policy["version"]
	if !ok {
		return "", errors.New("version is not specified")
	}
	return version.(string), nil
}

// ParseTrustPolicies creates policies from the given bytes of specified version.
// Current implementation only supports policy in version "1.0". New versions
// MUST be supported if added.
func ParseTrustPolicies(policyBytes []byte, version string) ([]*TrustPolicy, error) {
	if version == "1.0" {
		policyDocument := &PolicyDocument{}
		if err := json.Unmarshal(policyBytes, policyDocument); err != nil {
			return nil, err
		}
		return policyDocument.ListPolicies(), nil
	}
	return nil, fmt.Errorf("unsupported version: %v", version)
}

// mergePolicy merges given policies into a new one. Values of the override
// policy will override those of the base one.
func mergePolicy(base *TrustPolicy, override *TrustPolicy) *TrustPolicy {
	policy := base.deepCopy()

	if len(override.RegistryScopes) > 0 {
		policy.RegistryScopes = override.RegistryScopes
	}
	if override.SignatureVerification.Level != "" {
		policy.SignatureVerification.Level = override.SignatureVerification.Level
	}
	if override.SignatureVerification.Override != nil {
		mergeMaps(policy.SignatureVerification.Override, override.SignatureVerification.Override)
	}
	if len(override.TrustStores) > 0 {
		policy.TrustStores = override.TrustStores
	}
	if len(override.TrustedIdentities) > 0 {
		policy.TrustedIdentities = override.TrustedIdentities
	}

	return policy
}

func mergeMaps(base, override map[string]string) {
	if base == nil {
		base = make(map[string]string)
	}
	
	for k, v := range override {
		base[k] = v
	}
}