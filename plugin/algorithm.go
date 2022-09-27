package plugin

import (
	"errors"

	"github.com/notaryproject/notation-core-go/signature"
)

// one of the following supported key spec names.
//
// https://github.com/notaryproject/notaryproject/blob/main/signature-specification.md#algorithm-selection
const (
	RSA_2048 = "RSA-2048"
	RSA_3072 = "RSA-3072"
	RSA_4096 = "RSA-4096"
	EC_256   = "EC-256"
	EC_384   = "EC-384"
	EC_521   = "EC-521"
)

// one of the following supported hash algorithm names.
//
// https://github.com/notaryproject/notaryproject/blob/main/signature-specification.md#algorithm-selection
const (
	SHA_256 = "SHA-256"
	SHA_384 = "SHA-384"
	SHA_512 = "SHA-512"
)

// one of the following supported signing algorithm names.
//
// https://github.com/notaryproject/notaryproject/blob/main/signature-specification.md#algorithm-selection
const (
	ECDSA_SHA_256      = "ECDSA-SHA-256"
	ECDSA_SHA_384      = "ECDSA-SHA-384"
	ECDSA_SHA_512      = "ECDSA-SHA-512"
	RSASSA_PSS_SHA_256 = "RSASSA-PSS-SHA-256"
	RSASSA_PSS_SHA_384 = "RSASSA-PSS-SHA-384"
	RSASSA_PSS_SHA_512 = "RSASSA-PSS-SHA-512"
)

// KeySpecName returns the name of a keySpec according to the spec.
func KeySpecString(k signature.KeySpec) string {
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

// KeySpecHashName returns the name of hash function according to the spec.
func KeySpecHashString(k signature.KeySpec) string {
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

// ParseKeySpecFromName parses keySpec name to a signature.keySpec type.
func ParseKeySpec(raw string) (keySpec signature.KeySpec, err error) {
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
	default:
		keySpec = signature.KeySpec{}
		err = errors.New("unknown key spec")
	}
	return
}

// SigningAlgorithmName returns the signing algorithm name of an algorithm according to the spec.
func SigningAlgorithmString(alg signature.Algorithm) string {
	switch alg {
	case signature.AlgorithmES256:
		return ECDSA_SHA_256
	case signature.AlgorithmES384:
		return ECDSA_SHA_384
	case signature.AlgorithmES512:
		return ECDSA_SHA_512
	case signature.AlgorithmPS256:
		return RSASSA_PSS_SHA_256
	case signature.AlgorithmPS384:
		return RSASSA_PSS_SHA_384
	case signature.AlgorithmPS512:
		return RSASSA_PSS_SHA_512
	}
	return ""
}

// ParseSigningAlgorithFromName parses the signing algorithm name from a given string.
func ParseSigningAlgorithm(raw string) (signature.Algorithm, error) {
	switch raw {
	case ECDSA_SHA_256:
		return signature.AlgorithmES256, nil
	case ECDSA_SHA_384:
		return signature.AlgorithmES384, nil
	case ECDSA_SHA_512:
		return signature.AlgorithmES512, nil
	case RSASSA_PSS_SHA_256:
		return signature.AlgorithmPS256, nil
	case RSASSA_PSS_SHA_384:
		return signature.AlgorithmPS384, nil
	case RSASSA_PSS_SHA_512:
		return signature.AlgorithmPS512, nil
	}
	return 0, errors.New("unknown signing algorithm")
}
