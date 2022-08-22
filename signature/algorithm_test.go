package signature

import (
	"testing"

	"github.com/notaryproject/notation-core-go/signature"
)

// TODO: keySpec may change, need to check new spec
func TestKeySpecName(t *testing.T) {
	tests := []struct {
		name     string
		keySpec  signature.KeySpec
		expected string
	}{
		{
			name: "EC 256",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeEC,
				Size: 256,
			},
			expected: EC_256,
		},
		{
			name: "EC 384",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeEC,
				Size: 384,
			},
			expected: EC_384,
		},
		{
			name: "EC 521",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeEC,
				Size: 521,
			},
			expected: EC_521,
		},
		{
			name: "RSA 2048",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeRSA,
				Size: 2048,
			},
			expected: RSA_2048,
		},
		{
			name: "RSA 3072",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeRSA,
				Size: 3072,
			},
			expected: RSA_3072,
		},
		{
			name: "RSA 4096",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeRSA,
				Size: 4096,
			},
			expected: RSA_4096,
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
			if name := KeySpecName(tt.keySpec); name != tt.expected {
				t.Errorf("unexpected keySpec name, expect: %v, got: %v", tt.expected, name)
			}
		})
	}
}

// TODO: hash name may change, need to check new spec
func TestKeySpecHashName(t *testing.T) {
	tests := []struct {
		name     string
		keySpec  signature.KeySpec
		expected string
	}{
		{
			name: "EC 256",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeEC,
				Size: 256,
			},
			expected: SHA_256,
		},
		{
			name: "EC 384",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeEC,
				Size: 384,
			},
			expected: SHA_384,
		},
		{
			name: "EC 521",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeEC,
				Size: 521,
			},
			expected: SHA_512,
		},
		{
			name: "RSA 2048",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeRSA,
				Size: 2048,
			},
			expected: SHA_256,
		},
		{
			name: "RSA 3072",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeRSA,
				Size: 3072,
			},
			expected: SHA_384,
		},
		{
			name: "RSA 4096",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeRSA,
				Size: 4096,
			},
			expected: SHA_512,
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
			if name := KeySpecHashName(tt.keySpec); name != tt.expected {
				t.Errorf("unexpected keySpec hash function name, expect: %v, got: %v", tt.expected, name)
			}
		})
	}
}

func TestParseKeySpecFromName(t *testing.T) {
	tests := []struct {
		name     string
		expected signature.KeySpec
		raw      string
	}{
		{
			name: "EC 256",
			raw:  EC_256,
			expected: signature.KeySpec{
				Type: signature.KeyTypeEC,
				Size: 256,
			},
		},
		{
			name: "EC 384",
			raw:  EC_384,
			expected: signature.KeySpec{
				Type: signature.KeyTypeEC,
				Size: 384,
			},
		},
		{
			name: "EC 521",
			raw:  EC_521,
			expected: signature.KeySpec{
				Type: signature.KeyTypeEC,
				Size: 521,
			},
		},
		{
			name: "RSA 2048",
			raw:  RSA_2048,
			expected: signature.KeySpec{
				Type: signature.KeyTypeRSA,
				Size: 2048,
			},
		},
		{
			name: "RSA 3072",
			raw:  RSA_3072,
			expected: signature.KeySpec{
				Type: signature.KeyTypeRSA,
				Size: 3072,
			},
		},
		{
			name: "RSA 4096",
			raw:  RSA_4096,
			expected: signature.KeySpec{
				Type: signature.KeyTypeRSA,
				Size: 4096,
			},
		},
		{
			name: "Unsupported key spec",
			raw:  "unsuppored",
			expected: signature.KeySpec{
				Type: 0,
				Size: 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if keySpec := ParseKeySpecFromName(tt.raw); keySpec != tt.expected {
				t.Errorf("unexpected pared keySpec name, expect: %v, got: %v", tt.expected, keySpec)
			}
		})
	}
}
