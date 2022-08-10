package signature

import "github.com/notaryproject/notation-core-go/signature"

// one of the following key spec name
// https://github.com/notaryproject/notaryproject/blob/main/signature-specification.md#algorithm-selection
const (
	RSA_2048 = "RSA_2048"
	RSA_3072 = "RSA_3072"
	RSA_4096 = "RSA_4096"
	EC_256   = "EC_256"
	EC_384   = "EC_384"
	EC_521   = "EC_521"
)

// one of the following hash name
// https://github.com/notaryproject/notaryproject/blob/main/signature-specification.md#algorithm-selection
const (
	SHA_256 = "SHA_256"
	SHA_384 = "SHA_384"
	SHA_512 = "SHA_512"
)

// KeySpecName returns the name of a keySpec according to the spec
func KeySpecName(k signature.KeySpec) string {
	switch k.Type {
	case signature.KeyTypeEC:
		switch k.Size {
		case 256:
			return EC_256
		case 384:
			return EC_384
		case 521:
			return EC_521
		}
	case signature.KeyTypeRSA:
		switch k.Size {
		case 2048:
			return RSA_2048
		case 3072:
			return RSA_3072
		case 4096:
			return RSA_4096
		}
	}
	return ""
}

// KeySpecHashName returns the name of hash function according to the spec
func KeySpecHashName(k signature.KeySpec) string {
	switch k.Type {
	case signature.KeyTypeEC:
		switch k.Size {
		case 256:
			return SHA_256
		case 384:
			return SHA_384
		case 521:
			return SHA_512
		}
	case signature.KeyTypeRSA:
		switch k.Size {
		case 2048:
			return SHA_256
		case 3072:
			return SHA_384
		case 4096:
			return SHA_512
		}
	}
	return ""
}

// ParseKeySpecFromName parses keyspec name to a signature.keySpec type
func ParseKeySpecFromName(raw string) (keySpec signature.KeySpec) {
	switch raw {
	case RSA_2048:
		keySpec.Size = 2048
		keySpec.Type = signature.KeyTypeRSA
	case RSA_3072:
		keySpec.Size = 3072
		keySpec.Type = signature.KeyTypeRSA
	case RSA_4096:
		keySpec.Size = 4096
		keySpec.Type = signature.KeyTypeRSA
	case EC_256:
		keySpec.Size = 256
		keySpec.Type = signature.KeyTypeEC
	case EC_384:
		keySpec.Size = 384
		keySpec.Type = signature.KeyTypeEC
	case EC_521:
		keySpec.Size = 521
		keySpec.Type = signature.KeyTypeEC
	}
	return
}
