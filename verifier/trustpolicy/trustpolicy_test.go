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

func dummyOCIPolicyDocument() OCIDocument {
	return OCIDocument{
		Version: "1.0",
		TrustPolicies: []OCITrustPolicy{
			{
				Name:                  "test-statement-name",
				RegistryScopes:        []string{"registry.acme-rockets.io/software/net-monitor"},
				SignatureVerification: SignatureVerification{VerificationLevel: "strict"},
				TrustStores:           []string{"ca:valid-trust-store", "signingAuthority:valid-trust-store"},
				TrustedIdentities:     []string{"x509.subject:CN=Notation Test Root,O=Notary,L=Seattle,ST=WA,C=US"},
			},
		},
	}
}

func dummyBlobPolicyDocument() BlobDocument {
	return BlobDocument{
		Version: "1.0",
		BlobTrustPolicies: []BlobTrustPolicy{
			{
				Name:                  "test-statement-name",
				SignatureVerification: SignatureVerification{VerificationLevel: "strict"},
				TrustStores:           []string{"ca:valid-trust-store", "signingAuthority:valid-trust-store"},
				TrustedIdentities:     []string{"x509.subject:CN=Notation Test Root,O=Notary,L=Seattle,ST=WA,C=US"},
			},
		},
	}
}

// create testcase for validatePolicyCore method
func TestValidatePolicyCore(t *testing.T) {
	policyName := "test-statement-name"
	sigVerification := SignatureVerification{VerificationLevel: "strict"}
	// valid policy
	if err := validatePolicyCore(policyName, sigVerification, []string{"ca:valid-ts"}, []string{"*"}); err != nil {
		t.Errorf("validatePolicyCore returned error: '%v'", err)
	}

	// check valid skip SignatureVerification
	if err := validatePolicyCore(policyName, SignatureVerification{VerificationLevel: "skip"}, []string{}, []string{}); err != nil {
		t.Errorf("validatePolicyCore returned error: '%v'", err)
	}

	// check skip SignatureVerification doesn't has trust store and trusted identity
	expectedErr := "trust policy statement \"test-statement-name\" is set to skip signature verification but configured with trust stores and/or trusted identities, remove them if signature verification needs to be skipped"
	if err := validatePolicyCore(policyName, SignatureVerification{VerificationLevel: "skip"}, []string{"ca:valid-ts"}, []string{}); err == nil || err.Error() != expectedErr {
		t.Errorf("expected error '%s' but not found", expectedErr)
	}
	if err := validatePolicyCore(policyName, SignatureVerification{VerificationLevel: "skip"}, []string{}, []string{"x509:zoop"}); err == nil || err.Error() != expectedErr {
		t.Errorf("expected error '%s' but not found", expectedErr)
	}

	// empty policy name
	expectedErr = "a trust policy statement is missing a name, every statement requires a name"
	if err := validatePolicyCore("", sigVerification, []string{"ca:valid-ts"}, []string{"*"}); err == nil || err.Error() != expectedErr {
		t.Errorf("expected error '%s' but not found", expectedErr)
	}

	// invalid SignatureVerification
	expectedErr = "trust policy statement \"test-statement-name\" has invalid signatureVerification: signature verification level is empty or missing in the trust policy statement"
	if err := validatePolicyCore(policyName, SignatureVerification{}, []string{"ca:valid-ts"}, []string{"*"}); err == nil || err.Error() != expectedErr {
		t.Errorf("expected error '%s' but not found", expectedErr)
	}

	// invalid trust-store or trust-policy
	expectedErr = "trust policy statement \"test-statement-name\" is either missing trust stores or trusted identities, both must be specified"
	if err := validatePolicyCore(policyName, sigVerification, []string{}, []string{}); err == nil || err.Error() != expectedErr {
		t.Errorf("expected error '%s' but not found", expectedErr)
	}
	if err := validatePolicyCore(policyName, sigVerification, []string{"ca:valid-ts"}, []string{}); err == nil || err.Error() != expectedErr {
		t.Errorf("expected error '%s' but not found", expectedErr)
	}

	expectedErr = "trust policy statement \"test-statement-name\" uses an unsupported trust store type \"hola\" in trust store value \"hola:valid-ts\""
	if err := validatePolicyCore(policyName, sigVerification, []string{"hola:valid-ts"}, []string{"hola"}); err == nil || err.Error() != expectedErr {
		t.Errorf("expected error '%s' but not found", expectedErr)
	}

	expectedErr = "trust policy statement \"test-statement-name\" has trusted identity \"x509.subject\" missing separator"
	if err := validatePolicyCore(policyName, sigVerification, []string{"ca:valid-ts"}, []string{"x509.subject"}); err == nil || err.Error() != expectedErr {
		t.Errorf("expected error '%s' but not found", expectedErr)
	}
}

// TestValidateTrustedIdentities tests only valid x509.subjects are accepted
func TestValidateTrustStore(t *testing.T) {
	// valid trust-store
	if err := validateTrustStore("test-statement-name", []string{"ca:my-ts"}); err != nil {
		t.Errorf("validateTrustStore returned error: '%v", err)
	}

	// empty trust-store
	expectedErr := "trust policy statement \"test-statement-name\" has malformed trust store value \"\". The required format is <TrustStoreType>:<TrustStoreName>"
	if err := validateTrustStore("test-statement-name", []string{""}); err == nil || err.Error() != expectedErr {
		t.Errorf("expected error '%s' but not found", expectedErr)
	}

	// invalid trust-store type
	expectedErr = "trust policy statement \"test-statement-name\" uses an unsupported trust store type \"unknown\" in trust store value \"unknown:my-ts\""
	if err := validateTrustStore("test-statement-name", []string{"unknown:my-ts"}); err == nil || err.Error() != expectedErr {
		t.Errorf("expected error '%s' but not found", expectedErr)
	}

	// invalid trust-store directory name
	expectedErr = "trust policy statement \"test-statement-name\" uses an unsupported trust store name \"#@$@$\" in trust store value \"ca:#@$@$\". Named store name needs to follow [a-zA-Z0-9_.-]+ format"
	if err := validateTrustStore("test-statement-name", []string{"ca:#@$@$"}); err == nil || err.Error() != expectedErr {
		t.Errorf("expected error '%s' but not found", expectedErr)
	}
}

// TestValidateTrustedIdentities tests only valid x509.subjects are accepted
func TestValidateTrustedIdentities(t *testing.T) {
	// wildcard present with specific trusted identity throws error.
	err := validateTrustedIdentities("test-statement-name", []string{"*", "C=US, ST=WA, O=wabbit-network.io"})
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" uses a wildcard trusted identity '*', a wildcard identity cannot be used in conjunction with other values" {
		t.Fatalf("trusted identities with wildcard and specific identityshould return error")
	}

	// If empty trust policy throws error.
	err = validateTrustedIdentities("test-statement-name", []string{""})
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" has an empty trusted identity" {
		fmt.Println(err.Error())
		t.Fatalf("empty trusted identity should return error")
	}

	// No trusted identity prefix throws error
	err = validateTrustedIdentities("test-statement-name", []string{"C=US, ST=WA, O=wabbit-network.io, OU=org1"})
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" has trusted identity \"C=US, ST=WA, O=wabbit-network.io, OU=org1\" missing separator" {
		t.Fatalf("trusted identity without separator should return error")
	}

	// Accept unknown identity prefixes
	err = validateTrustedIdentities("test-statement-name", []string{"unknown:my-trusted-identity"})
	if err != nil {
		t.Fatalf("unknown identity prefix should not return an error. Error: %q", err)
	}

	// Validate x509.subject identities
	invalidDN := "x509.subject:,,,"
	err = validateTrustedIdentities("test-statement-name", []string{invalidDN})
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" has trusted identity \"x509.subject:,,,\" with invalid identity value: parsing distinguished name (DN) \",,,\" failed with err: incomplete type, value pair. A valid DN must contain 'C', 'ST', and 'O' RDN attributes at a minimum, and follow RFC 4514 standard" {
		t.Fatalf("invalid x509.subject identity should return error. Error : %q", err)
	}

	// Validate x509.subject with no value
	err = validateTrustedIdentities("test-statement-name", []string{"x509.subject:"})
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" has trusted identity \"x509.subject:\" without an identity value" {
		t.Fatalf("x509.subject identity without value should return error. Error : %q", err)
	}

	// Validate duplicate RDNs
	invalidDN = "x509.subject:C=US,C=IN"
	err = validateTrustedIdentities("test-statement-name", []string{invalidDN})
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" has trusted identity \"x509.subject:C=US,C=IN\" with invalid identity value: distinguished name (DN) \"C=US,C=IN\" has duplicate RDN attribute for \"C\", DN can only have unique RDN attributes" {
		t.Fatalf("invalid x509.subject identity should return error. Error : %q", err)
	}

	// Validate mandatory RDNs
	invalidDN = "x509.subject:C=US,ST=WA"
	err = validateTrustedIdentities("test-statement-name", []string{invalidDN})
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" has trusted identity \"x509.subject:C=US,ST=WA\" with invalid identity value: distinguished name (DN) \"C=US,ST=WA\" has no mandatory RDN attribute for \"O\", it must contain 'C', 'ST', and 'O' RDN attributes at a minimum" {
		t.Fatalf("invalid x509.subject identity should return error. Error : %q", err)
	}

	// DN may have optional RDNs
	validDN := "x509.subject:C=US,ST=WA,O=MyOrg,CustomRDN=CustomValue"
	err = validateTrustedIdentities("test-statement-name", []string{validDN})
	if err != nil {
		t.Fatalf("valid x509.subject identity should not return error. Error : %q", err)
	}

	// Validate rfc4514 DNs
	validDN1 := "x509.subject:C=US,ST=WA,O=MyOrg"
	validDN2 := "x509.subject:C=US,ST=WA,O=  My.  Org"
	validDN3 := "x509.subject:C=US,ST=WA,O=My \"special\" Org \\, \\; \\\\ others"
	err = validateTrustedIdentities("test-statement-name", []string{validDN1, validDN2, validDN3})
	if err != nil {
		t.Fatalf("valid x509.subject identity should not return error. Error : %q", err)
	}

	// Validate overlapping DNs
	validDN1 = "x509.subject:C=US,ST=WA,O=MyOrg"
	validDN2 = "x509.subject:C=US,ST=WA,O=MyOrg,X=Y"
	err = validateTrustedIdentities("test-statement-name", []string{validDN1, validDN2})
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" has overlapping x509 trustedIdentities, \"x509.subject:C=US,ST=WA,O=MyOrg\" overlaps with \"x509.subject:C=US,ST=WA,O=MyOrg,X=Y\"" {
		t.Fatalf("overlapping DNs should return error")
	}

	// Validate multi-valued RDNs
	multiValuedRUN := "x509.subject:C=US+ST=WA,O=MyOrg"
	err = validateTrustedIdentities("test-statement-name", []string{multiValuedRUN})
	if err == nil || err.Error() != "trust policy statement \"test-statement-name\" has trusted identity \"x509.subject:C=US+ST=WA,O=MyOrg\" with invalid identity value: distinguished name (DN) \"C=US+ST=WA,O=MyOrg\" has multi-valued RDN attributes, remove multi-valued RDN attributes as they are not supported" {
		t.Fatalf("multi-valued RDN should return error. Error : %q", err)
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

func TestGetDocument(t *testing.T) {
	dir.UserConfigDir = "/"
	var ociDoc OCIDocument
	var blobDoc BlobDocument
	tests := []struct {
		name             string
		expectedDocument any
		actualDocument   any
	}{
		{
			name:             "valid OCI policy file",
			expectedDocument: dummyOCIPolicyDocument(),
			actualDocument:   &ociDoc,
		},
		{
			name:             "valid Blob policy file",
			expectedDocument: dummyBlobPolicyDocument(),
			actualDocument:   &blobDoc,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempRoot := t.TempDir()
			path := filepath.Join(tempRoot, "trustpolicy.json")
			policyJson, _ := json.Marshal(tt.expectedDocument)
			if err := os.WriteFile(path, policyJson, 0600); err != nil {
				t.Fatalf("TestGetDocument write policy file failed. Error: %v", err)
			}
			t.Cleanup(func() { os.RemoveAll(tempRoot) })

			if err := getDocument(path, tt.actualDocument); err != nil {
				t.Fatalf("getDocument() should not throw error for an existing policy file. Error: %v", err)
			}
		})
	}
}

func TestGetDocumentErrors(t *testing.T) {
	dir.UserConfigDir = "/"
	t.Run("non-existing policy file", func(t *testing.T) {
		var doc OCIDocument
		if err := getDocument("blaah", &doc); err == nil || err.Error() != fmt.Sprintf("trust policy is not present. To create a trust policy, see: %s", trustPolicyLink) {
			t.Fatalf("getDocument() should throw error for non existent policy")
		}
	})

	t.Run("invalid json file", func(t *testing.T) {
		tempRoot := t.TempDir()
		path := filepath.Join(tempRoot, "invalid.json")
		if err := os.WriteFile(path, []byte(`{"invalid`), 0600); err != nil {
			t.Fatalf("creation of invalid policy file failed. Error: %v", err)
		}
		t.Cleanup(func() { os.RemoveAll(tempRoot) })

		var doc OCIDocument
		if err := getDocument(path, &doc); err == nil || err.Error() != fmt.Sprintf("malformed trust policy. To create a trust policy, see: %s", trustPolicyLink) {
			t.Fatalf("getDocument() should throw error for invalid policy file. Error: %v", err)
		}
	})

	t.Run("policy file with bad permissions", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("skipping test on Windows")
		}
		tempRoot := t.TempDir()
		policyJson, _ := json.Marshal([]byte("Some String"))
		path := filepath.Join(tempRoot, "trustpolicy.json")
		if err := os.WriteFile(path, policyJson, 0000); err != nil {
			t.Fatalf("creation of invalid permission policy file failed. Error: %v", err)
		}
		expectedErrMsg := fmt.Sprintf("unable to read trust policy due to file permissions, please verify the permissions of %s", path)
		var doc OCIDocument
		if err := getDocument(path, &doc); err == nil || err.Error() != expectedErrMsg {
			t.Errorf("getDocument() should throw error for a policy file with bad permissions. "+
				"Expected error: '%v'qq but found '%v'", expectedErrMsg, err.Error())
		}
	})

	t.Run("symlink policy file", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("skipping test on Windows")
		}
		tempRoot := t.TempDir()
		path := filepath.Join(tempRoot, "trustpolicy.json")
		if err := os.WriteFile(path, []byte(`{"invalid`), 0600); err != nil {
			t.Fatalf("creation of policy file failed. Error: %v", err)
		}

		symlinkPath := filepath.Join(tempRoot, "invalid.json")
		if err := os.Symlink(path, symlinkPath); err != nil {
			t.Fatalf("creation of symlink for policy file failed. Error: %v", err)
		}
		var doc OCIDocument
		if err := getDocument(symlinkPath, &doc); err == nil || !strings.HasPrefix(err.Error(), "trust policy is not a regular file (symlinks are not supported)") {
			t.Fatalf("getDocument() should throw error for a symlink policy file. Error: %v", err)
		}
	})
}
