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

package pkix

import "testing"

func TestParseDistinguishedName(t *testing.T) {
	// Test cases
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid DN",
			input:   "C=US,ST=California,O=Notary Project",
			wantErr: false,
		},
		{
			name:    "valid DN with State alias",
			input:   "C=US,S=California,O=Notary Project",
			wantErr: false,
		},
		{
			name:    "invalid DN",
			input:   "C=US,ST=California",
			wantErr: true,
		},
		{
			name:    "invalid DN without State",
			input:   "C=US,O=Notary Project",
			wantErr: true,
		},
		{
			name:    "invalid DN without State",
			input:   "invalid",
			wantErr: true,
		},
		{
			name:    "duplicate RDN attribute",
			input:   "C=US,ST=California,O=Notary Project,S=California",
			wantErr: true,
		},
		{
			name:    "unsupported DN =#",
			input:   "C=US,ST=California,O=Notary Project=#",
			wantErr: true,
		},
		{
			name:    "multi-valued RDN attributes",
			input:   "OU=Sales+CN=J.  Smith,DC=example,DC=net",
			wantErr: true,
		},
	}

	// Run tests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseDistinguishedName(tt.input)
			if tt.wantErr != (err != nil) {
				t.Errorf("ParseDistinguishedName() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsSubsetDN(t *testing.T) {
	// Test cases
	tests := []struct {
		name string
		dn1  map[string]string
		dn2  map[string]string
		want bool
	}{
		{
			name: "subset DN",
			dn1: map[string]string{
				"C":  "US",
				"ST": "California",
				"O":  "Notary Project",
			},
			dn2: map[string]string{
				"C":  "US",
				"ST": "California",
				"O":  "Notary Project",
				"L":  "Los Angeles",
			},
			want: true,
		},
		{
			name: "not subset DN",
			dn1: map[string]string{
				"C":  "US",
				"ST": "California",
				"O":  "Notary Project",
			},
			dn2: map[string]string{
				"C":  "US",
				"ST": "California",
				"O":  "Notary Project 2",
				"L":  "Los Angeles",
				"CN": "Notary",
			},
			want: false,
		},
		{
			name: "not subset DN 2",
			dn1: map[string]string{
				"C":  "US",
				"ST": "California",
				"O":  "Notary Project",
				"CN": "Notary",
			},
			dn2: map[string]string{
				"C":  "US",
				"ST": "California",
				"O":  "Notary Project",
				"L":  "Los Angeles",
			},
			want: false,
		},
	}

	// Run tests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSubsetDN(tt.dn1, tt.dn2); got != tt.want {
				t.Errorf("IsSubsetDN() = %v, want %v", got, tt.want)
			}
		})
	}
}
