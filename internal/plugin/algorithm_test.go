package plugin

import (
	"testing"

	"github.com/notaryproject/notation-core-go/signature"
)

func TestKeySpecString(t *testing.T) {
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
			if name := KeySpecString(tt.keySpec); name != tt.expected {
				t.Fatalf("unexpected keySpec name, expect: %v, got: %v", tt.expected, name)
			}
		})
	}
}

func TestKeySpecHashString(t *testing.T) {
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
			if name := KeySpecHashString(tt.keySpec); name != tt.expected {
				t.Fatalf("unexpected keySpec hash function name, expect: %v, got: %v", tt.expected, name)
			}
		})
	}
}

func TestParseKeySpec(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		expected  signature.KeySpec
		expectErr bool
	}{
		{
			name: "EC 256",
			raw:  EC_256,
			expected: signature.KeySpec{
				Type: signature.KeyTypeEC,
				Size: 256,
			},
			expectErr: false,
		},
		{
			name: "EC 384",
			raw:  EC_384,
			expected: signature.KeySpec{
				Type: signature.KeyTypeEC,
				Size: 384,
			},
			expectErr: false,
		},
		{
			name: "EC 521",
			raw:  EC_521,
			expected: signature.KeySpec{
				Type: signature.KeyTypeEC,
				Size: 521,
			},
			expectErr: false,
		},
		{
			name: "RSA 2048",
			raw:  RSA_2048,
			expected: signature.KeySpec{
				Type: signature.KeyTypeRSA,
				Size: 2048,
			},
			expectErr: false,
		},
		{
			name: "RSA 3072",
			raw:  RSA_3072,
			expected: signature.KeySpec{
				Type: signature.KeyTypeRSA,
				Size: 3072,
			},
			expectErr: false,
		},
		{
			name: "RSA 4096",
			raw:  RSA_4096,
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
			keySpec, err := ParseKeySpec(tt.raw)
			if keySpec != tt.expected {
				t.Fatalf("unexpected parsed keySpec name, expect: %v, got: %v", tt.expected, keySpec)
			}
			if (err != nil) != tt.expectErr {
				t.Fatalf("expect ParseKeySpec error: %v, got: %v", tt.expectErr, err)
			}
		})
	}
}

func TestSigningAlgorithmString(t *testing.T) {
	tests := []struct {
		name     string
		alg      signature.Algorithm
		expected string
	}{
		{
			name:     "RSASSA-PSS with SHA-256",
			alg:      signature.AlgorithmPS256,
			expected: RSASSA_PSS_SHA_256,
		},
		{
			name:     "RSASSA-PSS with SHA-384",
			alg:      signature.AlgorithmPS384,
			expected: RSASSA_PSS_SHA_384,
		},
		{
			name:     "RSASSA-PSS with SHA-512",
			alg:      signature.AlgorithmPS512,
			expected: RSASSA_PSS_SHA_512,
		},
		{
			name:     "ECDSA on secp256r1 with SHA-256",
			alg:      signature.AlgorithmES256,
			expected: ECDSA_SHA_256,
		},
		{
			name:     "ECDSA on secp384r1 with SHA-384",
			alg:      signature.AlgorithmES384,
			expected: ECDSA_SHA_384,
		},
		{
			name:     "ECDSA on secp521r1 with SHA-512",
			alg:      signature.AlgorithmES512,
			expected: ECDSA_SHA_512,
		},
		{
			name:     "unsupported algorithm",
			alg:      0,
			expected: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if name := SigningAlgorithmString(tt.alg); name != tt.expected {
				t.Fatalf("unexpected signing algorithm name, expect: %v, got: %v", tt.expected, name)
			}
		})
	}
}

func TestParseSigningAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		expected  signature.Algorithm
		expectErr bool
	}{
		{
			name:      "RSASSA-PSS with SHA-256",
			raw:       RSASSA_PSS_SHA_256,
			expected:  signature.AlgorithmPS256,
			expectErr: false,
		},
		{
			name:      "RSASSA-PSS with SHA-384",
			raw:       RSASSA_PSS_SHA_384,
			expected:  signature.AlgorithmPS384,
			expectErr: false,
		},
		{
			name:      "RSASSA-PSS with SHA-512",
			raw:       RSASSA_PSS_SHA_512,
			expected:  signature.AlgorithmPS512,
			expectErr: false,
		},
		{
			name:      "ECDSA on secp256r1 with SHA-256",
			raw:       ECDSA_SHA_256,
			expected:  signature.AlgorithmES256,
			expectErr: false,
		},
		{
			name:      "ECDSA on secp384r1 with SHA-384",
			raw:       ECDSA_SHA_384,
			expected:  signature.AlgorithmES384,
			expectErr: false,
		},
		{
			name:      "ECDSA on secp521r1 with SHA-512",
			raw:       ECDSA_SHA_512,
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
			alg, err := ParseSigningAlgorithm(tt.raw)
			if alg != tt.expected {
				t.Fatalf("unexpected signing algorithm, expect: %v, got: %v", tt.expected, alg)
			}
			if (err != nil) != tt.expectErr {
				t.Fatalf("expect ParseSigningAlgorithFromName error: %v, got: %v", tt.expectErr, err)
			}
		})
	}
}
