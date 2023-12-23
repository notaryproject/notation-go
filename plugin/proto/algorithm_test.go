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

package proto

import (
	"testing"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-plugin-framework-go/plugin"
)

func TestEncodeKeySpec(t *testing.T) {
	tests := []struct {
		name     string
		keySpec  signature.KeySpec
		expected plugin.KeySpec
	}{
		{
			name: "EC 256",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeEC,
				Size: 256,
			},
			expected: plugin.KeySpecEC256,
		},
		{
			name: "EC 384",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeEC,
				Size: 384,
			},
			expected: plugin.KeySpecEC384,
		},
		{
			name: "EC 521",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeEC,
				Size: 521,
			},
			expected: plugin.KeySpecEC521,
		},
		{
			name: "RSA 2048",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeRSA,
				Size: 2048,
			},
			expected: plugin.KeySpecRSA2048,
		},
		{
			name: "RSA 3072",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeRSA,
				Size: 3072,
			},
			expected: plugin.KeySpecRSA3072,
		},
		{
			name: "RSA 4096",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeRSA,
				Size: 4096,
			},
			expected: plugin.KeySpecRSA4096,
		},
		{
			name: "Unsupported key spec",
			keySpec: signature.KeySpec{
				Type: 0,
				Size: 0,
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if name, _ := EncodeKeySpec(tt.keySpec); name != tt.expected {
				t.Fatalf("unexpected keySpec name, expect: %v, got: %v", tt.expected, name)
			}
		})
	}
}

func TestHashAlgorithmFromKeySpec(t *testing.T) {
	tests := []struct {
		name     string
		keySpec  signature.KeySpec
		expected plugin.HashAlgorithm
	}{
		{
			name: "EC 256",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeEC,
				Size: 256,
			},
			expected: plugin.HashAlgorithmSHA256,
		},
		{
			name: "EC 384",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeEC,
				Size: 384,
			},
			expected: plugin.HashAlgorithmSHA384,
		},
		{
			name: "EC 521",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeEC,
				Size: 521,
			},
			expected: plugin.HashAlgorithmSHA512,
		},
		{
			name: "RSA 2048",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeRSA,
				Size: 2048,
			},
			expected: plugin.HashAlgorithmSHA256,
		},
		{
			name: "RSA 3072",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeRSA,
				Size: 3072,
			},
			expected: plugin.HashAlgorithmSHA384,
		},
		{
			name: "RSA 4096",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeRSA,
				Size: 4096,
			},
			expected: plugin.HashAlgorithmSHA512,
		},
		{
			name: "Unsupported key spec",
			keySpec: signature.KeySpec{
				Type: 0,
				Size: 0,
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if name, _ := HashAlgorithmFromKeySpec(tt.keySpec); name != tt.expected {
				t.Fatalf("unexpected keySpec hash function name, expect: %v, got: %v", tt.expected, name)
			}
		})
	}
}

func TestDecodeKeySpec(t *testing.T) {
	tests := []struct {
		name      string
		raw       plugin.KeySpec
		expected  signature.KeySpec
		expectErr bool
	}{
		{
			name: "EC 256",
			raw:  plugin.KeySpecEC256,
			expected: signature.KeySpec{
				Type: signature.KeyTypeEC,
				Size: 256,
			},
			expectErr: false,
		},
		{
			name: "EC 384",
			raw:  plugin.KeySpecEC384,
			expected: signature.KeySpec{
				Type: signature.KeyTypeEC,
				Size: 384,
			},
			expectErr: false,
		},
		{
			name: "EC 521",
			raw:  plugin.KeySpecEC521,
			expected: signature.KeySpec{
				Type: signature.KeyTypeEC,
				Size: 521,
			},
			expectErr: false,
		},
		{
			name: "RSA 2048",
			raw:  plugin.KeySpecRSA2048,
			expected: signature.KeySpec{
				Type: signature.KeyTypeRSA,
				Size: 2048,
			},
			expectErr: false,
		},
		{
			name: "RSA 3072",
			raw:  plugin.KeySpecRSA3072,
			expected: signature.KeySpec{
				Type: signature.KeyTypeRSA,
				Size: 3072,
			},
			expectErr: false,
		},
		{
			name: "RSA 4096",
			raw:  plugin.KeySpecRSA4096,
			expected: signature.KeySpec{
				Type: signature.KeyTypeRSA,
				Size: 4096,
			},
			expectErr: false,
		},
		{
			name:      "Unsupported key spec",
			raw:       "unsuppored",
			expected:  signature.KeySpec{},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keySpec, err := DecodeKeySpec(tt.raw)
			if keySpec != tt.expected {
				t.Fatalf("unexpected parsed keySpec name, expect: %v, got: %v", tt.expected, keySpec)
			}
			if (err != nil) != tt.expectErr {
				t.Fatalf("expect ParseKeySpec error: %v, got: %v", tt.expectErr, err)
			}
		})
	}
}

func TestEncodeSigningAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		alg      signature.Algorithm
		expected plugin.SignatureAlgorithm
	}{
		{
			name:     "RSASSA-PSS with SHA-256",
			alg:      signature.AlgorithmPS256,
			expected: plugin.SignatureAlgorithmRSASSA_PSS_SHA256,
		},
		{
			name:     "RSASSA-PSS with SHA-384",
			alg:      signature.AlgorithmPS384,
			expected: plugin.SignatureAlgorithmRSASSA_PSS_SHA384,
		},
		{
			name:     "RSASSA-PSS with SHA-512",
			alg:      signature.AlgorithmPS512,
			expected: plugin.SignatureAlgorithmRSASSA_PSS_SHA512,
		},
		{
			name:     "ECDSA on secp256r1 with SHA-256",
			alg:      signature.AlgorithmES256,
			expected: plugin.SignatureAlgorithmECDSA_SHA256,
		},
		{
			name:     "ECDSA on secp384r1 with SHA-384",
			alg:      signature.AlgorithmES384,
			expected: plugin.SignatureAlgorithmECDSA_SHA384,
		},
		{
			name:     "ECDSA on secp521r1 with SHA-512",
			alg:      signature.AlgorithmES512,
			expected: plugin.SignatureAlgorithmECDSA_SHA512,
		},
		{
			name:     "unsupported algorithm",
			alg:      0,
			expected: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if name, _ := EncodeSigningAlgorithm(tt.alg); name != tt.expected {
				t.Fatalf("unexpected signing algorithm name, expect: %v, got: %v", tt.expected, name)
			}
		})
	}
}

func TestParseSigningAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		raw       plugin.SignatureAlgorithm
		expected  signature.Algorithm
		expectErr bool
	}{
		{
			name:      "RSASSA-PSS with SHA-256",
			raw:       plugin.SignatureAlgorithmRSASSA_PSS_SHA256,
			expected:  signature.AlgorithmPS256,
			expectErr: false,
		},
		{
			name:      "RSASSA-PSS with SHA-384",
			raw:       plugin.SignatureAlgorithmRSASSA_PSS_SHA384,
			expected:  signature.AlgorithmPS384,
			expectErr: false,
		},
		{
			name:      "RSASSA-PSS with SHA-512",
			raw:       plugin.SignatureAlgorithmRSASSA_PSS_SHA512,
			expected:  signature.AlgorithmPS512,
			expectErr: false,
		},
		{
			name:      "ECDSA on secp256r1 with SHA-256",
			raw:       plugin.SignatureAlgorithmECDSA_SHA256,
			expected:  signature.AlgorithmES256,
			expectErr: false,
		},
		{
			name:      "ECDSA on secp384r1 with SHA-384",
			raw:       plugin.SignatureAlgorithmECDSA_SHA384,
			expected:  signature.AlgorithmES384,
			expectErr: false,
		},
		{
			name:      "ECDSA on secp521r1 with SHA-512",
			raw:       plugin.SignatureAlgorithmECDSA_SHA512,
			expected:  signature.AlgorithmES512,
			expectErr: false,
		},
		{
			name:      "unsupported algorithm",
			raw:       "",
			expected:  0,
			expectErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alg, err := DecodeSigningAlgorithm(tt.raw)
			if alg != tt.expected {
				t.Fatalf("unexpected signing algorithm, expect: %v, got: %v", tt.expected, alg)
			}
			if (err != nil) != tt.expectErr {
				t.Fatalf("expect ParseSigningAlgorithFromName error: %v, got: %v", tt.expectErr, err)
			}
		})
	}
}
