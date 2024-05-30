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
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/notaryproject/notation-go/dir"
)

func TestLoadBlobDocument(t *testing.T) {
	tempRoot := t.TempDir()
	dir.UserConfigDir = tempRoot
	path := filepath.Join(tempRoot, "trustpolicy.blob.json")
	policyJson, _ := json.Marshal(dummyBlobPolicyDocument())
	if err := os.WriteFile(path, policyJson, 0600); err != nil {
		t.Fatalf("TestLoadBlobDocument write policy file failed. Error: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tempRoot) })

	if _, err := LoadBlobDocument(); err != nil {
		t.Fatalf("LoadBlobDocument() should not throw error for an existing policy file. Error: %v", err)
	}
}

func TestValidate_BlobDocument(t *testing.T) {
	policyDoc := dummyBlobPolicyDocument()
	if err := policyDoc.Validate(); err != nil {
		t.Fatalf("Validate() returned error: %v", err)
	}
}

func TestValidate_BlobDocument_Error(t *testing.T) {
	// Sanity check
	var nilPolicyDoc *BlobDocument
	err := nilPolicyDoc.Validate()
	if err == nil || err.Error() != "blob trust policy document cannot be nil" {
		t.Fatalf("nil policyDoc should return error")
	}

	// empty Version
	policyDoc := dummyBlobPolicyDocument()
	policyDoc.Version = ""
	err = policyDoc.Validate()
	if err == nil || err.Error() != "blob trust policy has empty version, version must be specified" {
		t.Fatalf("empty version should return error")
	}

	// Invalid Version
	policyDoc = dummyBlobPolicyDocument()
	policyDoc.Version = "invalid"
	err = policyDoc.Validate()
	if err == nil || err.Error() != "blob trust policy document uses unsupported version \"invalid\"" {
		t.Fatalf("invalid version should return error")
	}

	// No Policy Statements
	policyDoc = dummyBlobPolicyDocument()
	policyDoc.TrustPolicies = nil
	err = policyDoc.Validate()
	if err == nil || err.Error() != "blob trust policy document can not have zero trust policy statements" {
		t.Fatalf("zero policy statements should return error")
	}

	// No Policy Statement Name
	policyDoc = dummyBlobPolicyDocument()
	policyDoc.TrustPolicies[0].Name = ""
	err = policyDoc.Validate()
	if err == nil || err.Error() != "blob trust policy: a trust policy statement is missing a name, every statement requires a name" {
		t.Fatalf("policy statement with no name should return an error")
	}

	// multiple global rust policy
	policyDoc = dummyBlobPolicyDocument()
	policyStatement1 := policyDoc.TrustPolicies[0].clone()
	policyStatement1.GlobalPolicy = true
	policyStatement2 := policyDoc.TrustPolicies[0].clone()
	policyStatement2.Name = "test-statement-name-2"
	policyStatement2.GlobalPolicy = true
	policyDoc.TrustPolicies = []BlobTrustPolicy{*policyStatement1, *policyStatement2}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "multiple blob trust policy statements have globalPolicy set to true. Only one trust policy statement should be marked as global policy" {
		t.Fatalf("policy statement with no name should return an error")
	}

	// Policy Document with duplicate policy statement names
	policyDoc = dummyBlobPolicyDocument()
	policyStatement1 = policyDoc.TrustPolicies[0].clone()
	policyStatement2 = policyDoc.TrustPolicies[0].clone()
	policyDoc.TrustPolicies = []BlobTrustPolicy{*policyStatement1, *policyStatement2}
	err = policyDoc.Validate()
	if err == nil || err.Error() != "multiple blob trust policy statements use the same name \"test-statement-name\", statement names must be unique" {
		t.Fatalf("policy statements with same name should return error")
	}
}

func TestGetApplicableTrustPolicy(t *testing.T) {
	policyDoc := dummyBlobPolicyDocument()

	policyStatement := policyDoc.TrustPolicies[0].clone()
	policyStatement1 := policyStatement.clone()
	policyStatement1.Name = "test-statement-name-1"
	policyStatement1.GlobalPolicy = true
	policyStatement2 := policyStatement.clone()
	policyStatement2.Name = "test-statement-name-2"
	policyDoc.TrustPolicies = []BlobTrustPolicy{*policyStatement, *policyStatement1, *policyStatement2}

	validateGetApplicableTrustPolicy(t, policyDoc, "test-statement-name-2", policyStatement2)
	validateGetApplicableTrustPolicy(t, policyDoc, "test-statement-name", policyStatement)
}

func TestGetApplicableTrustPolicy_Error(t *testing.T) {
	policyDoc := dummyBlobPolicyDocument()
	t.Run("empty policy name", func(t *testing.T) {
		_, err := policyDoc.GetApplicableTrustPolicy("")
		if err == nil || err.Error() != "policy name cannot be empty" {
			t.Fatalf("GetApplicableTrustPolicy() returned error: %v", err)
		}
	})

	t.Run("non existent policy name", func(t *testing.T) {
		_, err := policyDoc.GetApplicableTrustPolicy("blaah")
		if err == nil || err.Error() != "no applicable blob trust policy. Applicability for a given blob is determined by policy name" {
			t.Fatalf("GetApplicableTrustPolicy() returned error: %v", err)
		}
	})
}

func TestGetGlobalTrustPolicy(t *testing.T) {
	policyDoc := dummyBlobPolicyDocument()
	policyDoc.TrustPolicies[0].GlobalPolicy = true

	policy, err := policyDoc.GetGlobalTrustPolicy()
	if err != nil {
		t.Fatalf("GetGlobalTrustPolicy() returned error: %v", err)
	}

	if !reflect.DeepEqual(*policy, policyDoc.TrustPolicies[0]) {
		t.Fatalf("GetGlobalTrustPolicy() returned unexpected policy")
	}
}

func validateGetApplicableTrustPolicy(t *testing.T, policyDoc BlobDocument, policyName string, expectedPolicy *BlobTrustPolicy) {
	policy, err := policyDoc.GetApplicableTrustPolicy(policyName)
	if err != nil {
		t.Fatalf("GetApplicableTrustPolicy() returned error: %v", err)
	}

	if reflect.DeepEqual(policy, *expectedPolicy) {
		t.Fatalf("GetApplicableTrustPolicy() returned unexpected policy for %s", policyName)
	}
}
