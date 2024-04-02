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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/notaryproject/notation-go/dir"
)

func dummyPolicyStatement() (policyStatement TrustPolicy) {
	policyStatement = TrustPolicy{
		Name:                  "test-statement-name",
		RegistryScopes:        []string{"registry.acme-rockets.io/software/net-monitor"},
		SignatureVerification: SignatureVerification{VerificationLevel: "strict"},
		TrustStores:           []string{"ca:valid-trust-store", "signingAuthority:valid-trust-store"},
		TrustedIdentities:     []string{"x509.subject:CN=Notation Test Root,O=Notary,L=Seattle,ST=WA,C=US"},
	}
	return
}

func dummyPolicyDocument() (policyDoc Document) {
	policyDoc = Document{
		Version:       "1.0",
		TrustPolicies: []TrustPolicy{dummyPolicyStatement()},
	}
	return
}

// TestValidateValidPolicyDocument tests a happy policy document
func TestValidateValidPolicyDocument(t *testing.T) {
	policyDoc := dummyPolicyDocument()

	policyStatement1 := dummyPolicyStatement()

	policyStatement2 := dummyPolicyStatement()
	policyStatement2.Name = "test-statement-name-2"
	policyStatement2.RegistryScopes = []string{"registry.wabbit-networks.io/software/unsigned/net-utils"}
	policyStatement2.SignatureVerification = SignatureVerification{VerificationLevel: "permissive"}

	policyStatement3 := dummyPolicyStatement()
	policyStatement3.Name = "test-statement-name-3"
	policyStatement3.RegistryScopes = []string{"registry.acme-rockets.io/software/legacy/metrics"}
	policyStatement3.TrustStores = []string{}
	policyStatement3.TrustedIdentities = []string{}
	policyStatement3.SignatureVerification = SignatureVerification{VerificationLevel: "skip"}

	policyStatement4 := dummyPolicyStatement()
	policyStatement4.Name = "test-statement-name-4"
	policyStatement4.TrustStores = []string{"ca:valid-trust-store", "signingAuthority:valid-trust-store-2"}
	policyStatement4.RegistryScopes = []string{"*"}
	policyStatement4.SignatureVerification = SignatureVerification{VerificationLevel: "audit"}

	policyStatement5 := dummyPolicyStatement()
	policyStatement5.Name = "test-statement-name-5"
	policyStatement5.RegistryScopes = []string{"registry.acme-rockets2.io/software"}
	policyStatement5.TrustedIdentities = []string{"*"}
	policyStatement5.SignatureVerification = SignatureVerification{VerificationLevel: "strict"}

	policyDoc.TrustPolicies = []TrustPolicy{
		policyStatement1,
		policyStatement2,
		policyStatement3,
		policyStatement4,
		policyStatement5,
	}
	err := policyDoc.Validate()
	if err != nil {
		t.Fatalf("validation failed on a good policy document. Error : %q", err)
	}
}

// TestValidateTrustedIdentities tests only valid x509.subjects are accepted
func TestValidateTrustedIdentities(t *testing.T) {

	// No trusted identity prefix throws error
	policyDoc := dummyPolicyDocument()
	policyStatement := dummyPolicyStatement()
	policyStatement.TrustedIdentities = []string{"C=US, ST=WA, O=wabbit-network.io, OU=org1"}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err := policyDoc.Validate()
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" has trusted identity \"C=US, ST=WA, O=wabbit-network.io, OU=org1\" missing separator" {
		t.Fatalf("trusted identity without separator should return error")
	}

	// Accept unknown identity prefixes
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.TrustedIdentities = []string{"unknown:my-trusted-idenity"}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.Validate()
	if err != nil {
		t.Fatalf("unknown identity prefix should not return an error. Error: %q", err)
	}

	// Validate x509.subject identities
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	invalidDN := "x509.subject:,,,"
	policyStatement.TrustedIdentities = []string{invalidDN}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" has trusted identity \"x509.subject:,,,\" with invalid identity value: parsing distinguished name (DN) \",,,\" failed with err: incomplete type, value pair. A valid DN must contain 'C', 'ST', and 'O' RDN attributes at a minimum, and follow RFC 4514 standard" {
		t.Fatalf("invalid x509.subject identity should return error. Error : %q", err)
	}

	// Validate duplicate RDNs
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	invalidDN = "x509.subject:C=US,C=IN"
	policyStatement.TrustedIdentities = []string{invalidDN}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" has trusted identity \"x509.subject:C=US,C=IN\" with invalid identity value: distinguished name (DN) \"C=US,C=IN\" has duplicate RDN attribute for \"C\", DN can only have unique RDN attributes" {
		t.Fatalf("invalid x509.subject identity should return error. Error : %q", err)
	}

	// Validate mandatory RDNs
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	invalidDN = "x509.subject:C=US,ST=WA"
	policyStatement.TrustedIdentities = []string{invalidDN}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" has trusted identity \"x509.subject:C=US,ST=WA\" with invalid identity value: distinguished name (DN) \"C=US,ST=WA\" has no mandatory RDN attribute for \"O\", it must contain 'C', 'ST', and 'O' RDN attributes at a minimum" {
		t.Fatalf("invalid x509.subject identity should return error. Error : %q", err)
	}

	// DN may have optional RDNs
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	validDN := "x509.subject:C=US,ST=WA,O=MyOrg,CustomRDN=CustomValue"
	policyStatement.TrustedIdentities = []string{validDN}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.Validate()
	if err != nil {
		t.Fatalf("valid x509.subject identity should not return error. Error : %q", err)
	}

	// Validate rfc4514 DNs
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	validDN1 := "x509.subject:C=US,ST=WA,O=MyOrg"
	validDN2 := "x509.subject:C=US,ST=WA,O=  My.  Org"
	validDN3 := "x509.subject:C=US,ST=WA,O=My \"special\" Org \\, \\; \\\\ others"
	policyStatement.TrustedIdentities = []string{validDN1, validDN2, validDN3}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.Validate()
	if err != nil {
		t.Fatalf("valid x509.subject identity should not return error. Error : %q", err)
	}

	// Validate overlapping DNs
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	validDN1 = "x509.subject:C=US,ST=WA,O=MyOrg"
	validDN2 = "x509.subject:C=US,ST=WA,O=MyOrg,X=Y"
	policyStatement.TrustedIdentities = []string{validDN1, validDN2}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" has overlapping x509 trustedIdentities, \"x509.subject:C=US,ST=WA,O=MyOrg\" overlaps with \"x509.subject:C=US,ST=WA,O=MyOrg,X=Y\"" {
		t.Fatalf("overlapping DNs should return error")
	}

	// Validate multi-valued RDNs
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	multiValduedRDN := "x509.subject:C=US+ST=WA,O=MyOrg"
	policyStatement.TrustedIdentities = []string{multiValduedRDN}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" has trusted identity \"x509.subject:C=US+ST=WA,O=MyOrg\" with invalid identity value: distinguished name (DN) \"C=US+ST=WA,O=MyOrg\" has multi-valued RDN attributes, remove multi-valued RDN attributes as they are not supported" {
		t.Fatalf("multi-valued RDN should return error. Error : %q", err)
	}
}

// TestInvalidRegistryScopes tests invalid scopes are rejected
func TestInvalidRegistryScopes(t *testing.T) {
	invalidScopes := []string{
		"", "1:1", "a,b", "abcd", "1111", "1,2", "example.com/rep:tag",
		"example.com/rep/subrep/sub:latest", "example.com", "rep/rep2:latest",
		"repository", "10.10.10.10", "10.10.10.10:8080/rep/rep2:latest",
	}

	for _, scope := range invalidScopes {
		policyDoc := dummyPolicyDocument()
		policyStatement := dummyPolicyStatement()
		policyStatement.RegistryScopes = []string{scope}
		policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
		err := policyDoc.Validate()
		if err == nil || err.Error() != "registry scope \""+scope+"\" is not valid, make sure it is a fully qualified repository without the scheme, protocol or tag. For example domain.com/my/repository or a local scope like local/myOCILayout" {
			t.Fatalf("invalid registry scope should return error. Error : %q", err)
		}
	}

	// Test invalid scope with wild card suffix

	invalidWildCardScopes := []string{"example.com/*", "*/", "example*/", "ex*test"}
	for _, scope := range invalidWildCardScopes {
		policyDoc := dummyPolicyDocument()
		policyStatement := dummyPolicyStatement()
		policyStatement.RegistryScopes = []string{scope}
		policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
		err := policyDoc.Validate()
		if err == nil || err.Error() != "registry scope \""+scope+"\" with wild card(s) is not valid, make sure it is a fully qualified repository without the scheme, protocol or tag. For example domain.com/my/repository or a local scope like local/myOCILayout" {
			t.Fatalf("invalid registry scope should return error. Error : %q", err)
		}
	}
}

// TestValidRegistryScopes tests valid scopes are accepted
func TestValidRegistryScopes(t *testing.T) {
	validScopes := []string{
		"*", "example.com/rep", "example.com:8080/rep/rep2", "example.com/rep/subrep/subsub",
		"10.10.10.10:8080/rep/rep2", "domain/rep", "domain:1234/rep",
	}

	for _, scope := range validScopes {
		policyDoc := dummyPolicyDocument()
		policyStatement := dummyPolicyStatement()
		policyStatement.RegistryScopes = []string{scope}
		policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
		err := policyDoc.Validate()
		if err != nil {
			t.Fatalf("valid registry scope should not return error. Error : %q", err)
		}
	}
}

// TestValidatePolicyDocument calls policyDoc.Validate()
// and tests various validations on policy eliments
func TestValidateInvalidPolicyDocument(t *testing.T) {
	// Sanity check
	var nilPolicyDoc *Document
	err := nilPolicyDoc.Validate()
	if err == nil || err.Error() != "trust policy document cannot be nil" {
		t.Fatalf("nil policyDoc should return error")
	}

	// Invalid Version
	policyDoc := dummyPolicyDocument()
	policyDoc.Version = "invalid"
	err = policyDoc.Validate()
	if err == nil || err.Error() != "trust policy document uses unsupported version \"invalid\"" {
		t.Fatalf("invalid version should return error")
	}

	// No Policy Satements
	policyDoc = dummyPolicyDocument()
	policyDoc.TrustPolicies = nil
	err = policyDoc.Validate()
	if err == nil || err.Error() != "trust policy document can not have zero trust policy statements" {
		t.Fatalf("zero policy statements should return error")
	}

	// No Policy Satement Name
	policyDoc = dummyPolicyDocument()
	policyStatement := dummyPolicyStatement()
	policyStatement.Name = ""
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "a trust policy statement is missing a name, every statement requires a name" {
		t.Fatalf("policy statement with no name should return an error")
	}

	// No Registry Scopes
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.RegistryScopes = nil
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" has zero registry scopes, it must specify registry scopes with at least one value" {
		t.Fatalf("policy statement with registry scopes should return error")
	}

	// Multiple policy statements with same registry scope
	policyDoc = dummyPolicyDocument()
	policyStatement1 := dummyPolicyStatement()
	policyStatement2 := dummyPolicyStatement()
	policyStatement2.Name = "test-statement-name-2"
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement1, policyStatement2}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "registry scope \"registry.acme-rockets.io/software/net-monitor\" is present in multiple trust policy statements, one registry scope value can only be associated with one statement" {
		t.Fatalf("Policy statements with same registry scope should return error %q", err)
	}

	// Registry scopes with a wildcard
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.RegistryScopes = []string{"*", "registry.acme-rockets.io/software/net-monitor"}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" uses wildcard registry scope '*', a wildcard scope cannot be used in conjunction with other scope values" {
		t.Fatalf("policy statement with more than a wildcard registry scope should return error")
	}

	// Invlaid SignatureVerification
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.SignatureVerification = SignatureVerification{VerificationLevel: "invalid"}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" has invalid signatureVerification: invalid signature verification level \"invalid\"" {
		t.Fatalf("policy statement with invalid SignatureVerification should return error")
	}

	// strict SignatureVerification should have a trust store
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.TrustStores = []string{}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" is either missing trust stores or trusted identities, both must be specified" {
		t.Fatalf("strict SignatureVerification should have a trust store")
	}

	// strict SignatureVerification should have trusted identities
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.TrustedIdentities = []string{}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" is either missing trust stores or trusted identities, both must be specified" {
		t.Fatalf("strict SignatureVerification should have trusted identities")
	}

	// skip SignatureVerification should not have trust store or trusted identities
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.SignatureVerification = SignatureVerification{VerificationLevel: "skip"}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" is set to skip signature verification but configured with trust stores and/or trusted identities, remove them if signature verification needs to be skipped" {
		t.Fatalf("strict SignatureVerification should have trusted identities")
	}

	// Empty Trusted Identity should throw error
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.TrustedIdentities = []string{""}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" has an empty trusted identity" {
		t.Fatalf("policy statement with empty trusted identity should return error")
	}

	// Trusted Identity without spearator should throw error
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.TrustedIdentities = []string{"x509.subject"}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" has trusted identity \"x509.subject\" missing separator" {
		t.Fatalf("policy statement with trusted identity missing separator should return error")
	}

	// Empty Trusted Identity value should throw error
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.TrustedIdentities = []string{"x509.subject:"}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" has trusted identity \"x509.subject:\" without an identity value" {
		t.Fatalf("policy statement with trusted identity missing identity value should return error")
	}

	// trust store/trusted identites are optional for skip SignatureVerification
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.SignatureVerification = SignatureVerification{VerificationLevel: "skip"}
	policyStatement.TrustStores = []string{}
	policyStatement.TrustedIdentities = []string{}
	err = policyDoc.Validate()
	if err != nil {
		t.Fatalf("skip SignatureVerification should not require a trust store or trusted identities")
	}

	// Trust Store missing separator
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.TrustStores = []string{"ca"}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" has malformed trust store value \"ca\". The required format is <TrustStoreType>:<TrustStoreName>" {
		t.Fatalf("policy statement with trust store missing separator should return error")
	}

	// Invalid Trust Store type
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.TrustStores = []string{"invalid:test-trust-store"}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" uses an unsupported trust store type \"invalid\" in trust store value \"invalid:test-trust-store\"" {
		t.Fatalf("policy statement with invalid trust store type should return error")
	}

	// Empty Named Store
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.TrustStores = []string{"ca:"}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" uses an unsupported trust store name \"\" in trust store value \"ca:\". Named store name needs to follow [a-zA-Z0-9_.-]+ format" {
		t.Fatalf("policy statement with trust store missing named store should return error")
	}

	// trusted identities with a wildcard
	policyDoc = dummyPolicyDocument()
	policyStatement = dummyPolicyStatement()
	policyStatement.TrustedIdentities = []string{"*", "test-identity"}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" uses a wildcard trusted identity '*', a wildcard identity cannot be used in conjunction with other values" {
		t.Fatalf("policy statement with more than a wildcard trusted identity should return error")
	}

	// Policy Document with duplicate policy statement names
	policyDoc = dummyPolicyDocument()
	policyStatement1 = dummyPolicyStatement()
	policyStatement2 = dummyPolicyStatement()
	policyStatement2.RegistryScopes = []string{"registry.acme-rockets.io/software/legacy/metrics"}
	policyDoc.TrustPolicies = []TrustPolicy{policyStatement1, policyStatement2}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "multiple trust policy statements use the same name \"test-statement-name\", statement names must be unique" {
		t.Fatalf("policy statements with same name should return error")
	}
}

func TestGetVerificationLevel(t *testing.T) {
	tests := []struct {
		verificationLevel   SignatureVerification
		wantErr             bool
		verificationActions []ValidationAction
	}{
		{SignatureVerification{VerificationLevel: "strict"}, false, []ValidationAction{ActionEnforce, ActionEnforce, ActionEnforce, ActionEnforce, ActionEnforce}},
		{SignatureVerification{VerificationLevel: "permissive"}, false, []ValidationAction{ActionEnforce, ActionEnforce, ActionLog, ActionLog, ActionLog}},
		{SignatureVerification{VerificationLevel: "audit"}, false, []ValidationAction{ActionEnforce, ActionLog, ActionLog, ActionLog, ActionLog}},
		{SignatureVerification{VerificationLevel: "skip"}, false, []ValidationAction{ActionSkip, ActionSkip, ActionSkip, ActionSkip, ActionSkip}},
		{SignatureVerification{VerificationLevel: "invalid"}, true, []ValidationAction{}},
	}
	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {

			level, err := tt.verificationLevel.GetVerificationLevel()

			if tt.wantErr != (err != nil) {
				t.Fatalf("TestFindVerificationLevel Error: %q WantErr: %v", err, tt.wantErr)
			} else {
				for index, action := range tt.verificationActions {
					if action != level.Enforcement[ValidationTypes[index]] {
						t.Errorf("%q verification action should be %q for Verification Level %q", ValidationTypes[index], action, tt.verificationLevel)
					}
				}
			}
		})
	}
}

func TestCustomVerificationLevel(t *testing.T) {
	tests := []struct {
		customVerification  SignatureVerification
		wantErr             bool
		verificationActions []ValidationAction
	}{
		{SignatureVerification{VerificationLevel: "strict", Override: map[ValidationType]ValidationAction{"integrity": "log"}}, true, []ValidationAction{}},
		{SignatureVerification{VerificationLevel: "strict", Override: map[ValidationType]ValidationAction{"authenticity": "skip"}}, true, []ValidationAction{}},
		{SignatureVerification{VerificationLevel: "strict", Override: map[ValidationType]ValidationAction{"authenticTimestamp": "skip"}}, true, []ValidationAction{}},
		{SignatureVerification{VerificationLevel: "strict", Override: map[ValidationType]ValidationAction{"expiry": "skip"}}, true, []ValidationAction{}},
		{SignatureVerification{VerificationLevel: "skip", Override: map[ValidationType]ValidationAction{"authenticity": "log"}}, true, []ValidationAction{}},
		{SignatureVerification{VerificationLevel: "invalid", Override: map[ValidationType]ValidationAction{"authenticity": "log"}}, true, []ValidationAction{}},
		{SignatureVerification{VerificationLevel: "strict", Override: map[ValidationType]ValidationAction{"invalid": "log"}}, true, []ValidationAction{}},
		{SignatureVerification{VerificationLevel: "strict", Override: map[ValidationType]ValidationAction{"authenticity": "invalid"}}, true, []ValidationAction{}},
		{SignatureVerification{VerificationLevel: "strict", Override: map[ValidationType]ValidationAction{"authenticity": "log"}}, false, []ValidationAction{ActionEnforce, ActionLog, ActionEnforce, ActionEnforce, ActionEnforce}},
		{SignatureVerification{VerificationLevel: "permissive", Override: map[ValidationType]ValidationAction{"authenticity": "log"}}, false, []ValidationAction{ActionEnforce, ActionLog, ActionLog, ActionLog, ActionLog}},
		{SignatureVerification{VerificationLevel: "audit", Override: map[ValidationType]ValidationAction{"authenticity": "log"}}, false, []ValidationAction{ActionEnforce, ActionLog, ActionLog, ActionLog, ActionLog}},
		{SignatureVerification{VerificationLevel: "strict", Override: map[ValidationType]ValidationAction{"expiry": "log"}}, false, []ValidationAction{ActionEnforce, ActionEnforce, ActionEnforce, ActionLog, ActionEnforce}},
		{SignatureVerification{VerificationLevel: "permissive", Override: map[ValidationType]ValidationAction{"expiry": "log"}}, false, []ValidationAction{ActionEnforce, ActionEnforce, ActionLog, ActionLog, ActionLog}},
		{SignatureVerification{VerificationLevel: "audit", Override: map[ValidationType]ValidationAction{"expiry": "log"}}, false, []ValidationAction{ActionEnforce, ActionLog, ActionLog, ActionLog, ActionLog}},
		{SignatureVerification{VerificationLevel: "strict", Override: map[ValidationType]ValidationAction{"revocation": "log"}}, false, []ValidationAction{ActionEnforce, ActionEnforce, ActionEnforce, ActionEnforce, ActionLog}},
		{SignatureVerification{VerificationLevel: "permissive", Override: map[ValidationType]ValidationAction{"revocation": "log"}}, false, []ValidationAction{ActionEnforce, ActionEnforce, ActionLog, ActionLog, ActionLog}},
		{SignatureVerification{VerificationLevel: "audit", Override: map[ValidationType]ValidationAction{"revocation": "log"}}, false, []ValidationAction{ActionEnforce, ActionLog, ActionLog, ActionLog, ActionLog}},
		{SignatureVerification{VerificationLevel: "strict", Override: map[ValidationType]ValidationAction{"revocation": "skip"}}, false, []ValidationAction{ActionEnforce, ActionEnforce, ActionEnforce, ActionEnforce, ActionSkip}},
		{SignatureVerification{VerificationLevel: "permissive", Override: map[ValidationType]ValidationAction{"revocation": "skip"}}, false, []ValidationAction{ActionEnforce, ActionEnforce, ActionLog, ActionLog, ActionSkip}},
		{SignatureVerification{VerificationLevel: "audit", Override: map[ValidationType]ValidationAction{"revocation": "skip"}}, false, []ValidationAction{ActionEnforce, ActionLog, ActionLog, ActionLog, ActionSkip}},
		{SignatureVerification{VerificationLevel: "permissive", Override: map[ValidationType]ValidationAction{"authenticTimestamp": "log"}}, false, []ValidationAction{ActionEnforce, ActionEnforce, ActionLog, ActionLog, ActionLog}},
		{SignatureVerification{VerificationLevel: "audit", Override: map[ValidationType]ValidationAction{"authenticTimestamp": "log"}}, false, []ValidationAction{ActionEnforce, ActionLog, ActionLog, ActionLog, ActionLog}},
		{SignatureVerification{VerificationLevel: "strict", Override: map[ValidationType]ValidationAction{"authenticTimestamp": "log"}}, false, []ValidationAction{ActionEnforce, ActionEnforce, ActionLog, ActionEnforce, ActionEnforce}},
	}
	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			level, err := tt.customVerification.GetVerificationLevel()

			if tt.wantErr != (err != nil) {
				t.Fatalf("TestCustomVerificationLevel Error: %q WantErr: %v", err, tt.wantErr)
			} else {
				if !tt.wantErr && len(tt.verificationActions) == 0 {
					t.Errorf("test case isn't configured with VerificationActions")
				}
				for index, action := range tt.verificationActions {
					if action != level.Enforcement[ValidationTypes[index]] {
						t.Errorf("%q verification action should be %q for custom verification %q", ValidationTypes[index], action, tt.customVerification)
					}
				}
			}
		})
	}
}

// TestApplicableTrustPolicy tests filtering policies against registry scopes
func TestApplicableTrustPolicy(t *testing.T) {
	policyDoc := dummyPolicyDocument()

	policyStatement := dummyPolicyStatement()
	policyStatement.Name = "test-statement-name-1"
	registryScope := "registry.wabbit-networks.io/software/unsigned/net-utils"
	registryUri := fmt.Sprintf("%s@sha256:hash", registryScope)
	policyStatement.RegistryScopes = []string{registryScope}
	policyStatement.SignatureVerification = SignatureVerification{VerificationLevel: "strict"}

	policyDoc.TrustPolicies = []TrustPolicy{
		policyStatement,
	}
	// existing Registry Scope
	policy, err := (&policyDoc).GetApplicableTrustPolicy(registryUri)
	if policy.Name != policyStatement.Name || err != nil {
		t.Fatalf("getApplicableTrustPolicy should return %q for registry scope %q", policyStatement.Name, registryScope)
	}

	// non-existing Registry Scope
	policy, err = (&policyDoc).GetApplicableTrustPolicy("non.existing.scope/repo@sha256:hash")
	if policy != nil || err == nil || err.Error() != "artifact \"non.existing.scope/repo@sha256:hash\" has no applicable trust policy. Trust policy applicability for a given artifact is determined by registryScopes. To create a trust policy, see: https://notaryproject.dev/docs/quickstart/#create-a-trust-policy" {
		t.Fatalf("getApplicableTrustPolicy should return nil for non existing registry scope")
	}

	// wildcard registry scope
	wildcardStatement := dummyPolicyStatement()
	wildcardStatement.Name = "test-statement-name-2"
	wildcardStatement.RegistryScopes = []string{"*"}
	wildcardStatement.TrustStores = []string{}
	wildcardStatement.TrustedIdentities = []string{}
	wildcardStatement.SignatureVerification = SignatureVerification{VerificationLevel: "skip"}

	policyDoc.TrustPolicies = []TrustPolicy{
		policyStatement,
		wildcardStatement,
	}
	policy, err = (&policyDoc).GetApplicableTrustPolicy("some.registry.that/has.no.policy@sha256:hash")
	if policy.Name != wildcardStatement.Name || err != nil {
		t.Fatalf("getApplicableTrustPolicy should return wildcard policy for registry scope \"some.registry.that/has.no.policy\"")
	}
}

func TestLoadDocument(t *testing.T) {

	t.Run("non-existing policy file", func(t *testing.T) {
		tempRoot := t.TempDir()
		dir.UserConfigDir = tempRoot
		if _, err := LoadDocument(); err == nil || err.Error() != fmt.Sprintf("trust policy is not present. To create a trust policy, see: %s", trustPolicyLink) {
			t.Fatalf("TestLoadPolicyDocument should throw error for non existent policy")
		}
	})

	t.Run("invalid json file", func(t *testing.T) {
		tempRoot := t.TempDir()
		dir.UserConfigDir = tempRoot
		path := filepath.Join(tempRoot, "invalid.json")
		if err := os.WriteFile(path, []byte(`{"invalid`), 0600); err != nil {
			t.Fatalf("TestLoadPolicyDocument create invalid policy file failed. Error: %v", err)
		}
		if _, err := LoadDocument(); err == nil {
			t.Fatalf("TestLoadPolicyDocument should throw error for invalid policy file. Error: %v", err)
		}
	})

	t.Run("valid policy file", func(t *testing.T) {
		tempRoot := t.TempDir()
		dir.UserConfigDir = tempRoot
		path := filepath.Join(tempRoot, "trustpolicy.json")
		policyDoc1 := dummyPolicyDocument()
		policyJson, _ := json.Marshal(policyDoc1)
		if err := os.WriteFile(path, policyJson, 0600); err != nil {
			t.Fatalf("TestLoadPolicyDocument create valid policy file failed. Error: %v", err)
		}
		if _, err := LoadDocument(); err != nil {
			t.Fatalf("TestLoadPolicyDocument should not throw error for an existing policy file. Error: %v", err)
		}
	})

	t.Run("policy file with bad permissions", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("skipping test on Windows")
		}
		tempRoot := t.TempDir()
		dir.UserConfigDir = tempRoot
		policyJson, _ := json.Marshal([]byte("Some String"))
		path := filepath.Join(tempRoot, "trustpolicy.json")
		if err := os.WriteFile(path, policyJson, 0000); err != nil {
			t.Fatalf("TestLoadPolicyDocument write policy file failed. Error: %v", err)
		}
		expectedErrMsg := fmt.Sprintf("unable to read trust policy due to file permissions, please verify the permissions of %s", path)
		_, err := LoadDocument()
		if err == nil || err.Error() != expectedErrMsg {
			t.Errorf("TestLoadPolicyDocument should throw error for a policy file with bad permissions. "+
				"Expected error: '%v'qq but found '%v'", expectedErrMsg, err.Error())
		}
	})

	t.Run("symlink policy file", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("skipping test on Windows")
		}
		tempRoot := t.TempDir()
		dir.UserConfigDir = tempRoot

		os.Symlink("some/filepath", filepath.Join(tempRoot, "trustpolicy.json"))
		_, err := LoadDocument()
		if err == nil || !strings.HasPrefix(err.Error(), "trust policy is not a regular file (symlinks are not supported)") {
			t.Fatalf("TestLoadPolicyDocument should throw error for a symlink policy file. Error: %v", err)
		}
	})
}
