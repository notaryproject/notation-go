package proto

import (
	"errors"
	"fmt"

	"github.com/notaryproject/notation-core-go/signature"
)

// KeySpec is type of the signing algorithm, including algorithm and size.
type KeySpec string

// one of the following supported key spec names.
//
// https://github.com/notaryproject/notaryproject/blob/main/specs/signature-specification.md#algorithm-selection
const (
	KeySpecRSA2048 KeySpec = "RSA-2048"
	KeySpecRSA3072 KeySpec = "RSA-3072"
	KeySpecRSA4096 KeySpec = "RSA-4096"
	KeySpecEC256   KeySpec = "EC-256"
	KeySpecEC384   KeySpec = "EC-384"
	KeySpecEC521   KeySpec = "EC-521"
)

// EncodeKeySpec returns the name of a keySpec according to the spec.
func EncodeKeySpec(k signature.KeySpec) (KeySpec, error) {
	switch k.Type {
	case signature.KeyTypeEC:
		switch k.Size {
		case 256:
			return KeySpecEC256, nil
		case 384:
			return KeySpecEC384, nil
		case 521:
			return KeySpecEC521, nil
		}
	case signature.KeyTypeRSA:
		switch k.Size {
		case 2048:
			return KeySpecRSA2048, nil
		case 3072:
			return KeySpecRSA3072, nil
		case 4096:
			return KeySpecRSA4096, nil
		}
	}
	return "", fmt.Errorf("invalid KeySpec %q", k)
}

// DecodeKeySpec parses keySpec name to a signature.keySpec type.
func DecodeKeySpec(k KeySpec) (keySpec signature.KeySpec, err error) {
	switch k {
	case KeySpecRSA2048:
		keySpec.Size = 2048
		keySpec.Type = signature.KeyTypeRSA
	case KeySpecRSA3072:
		keySpec.Size = 3072
		keySpec.Type = signature.KeyTypeRSA
	case KeySpecRSA4096:
		keySpec.Size = 4096
		keySpec.Type = signature.KeyTypeRSA
	case KeySpecEC256:
		keySpec.Size = 256
		keySpec.Type = signature.KeyTypeEC
	case KeySpecEC384:
		keySpec.Size = 384
		keySpec.Type = signature.KeyTypeEC
	case KeySpecEC521:
		keySpec.Size = 521
		keySpec.Type = signature.KeyTypeEC
	default:
		keySpec = signature.KeySpec{}
		err = errors.New("unknown key spec")
	}
	return
}

// HashAlgorithm is the type of a hash algorithm.
type HashAlgorithm string

// one of the following supported hash algorithm names.
//
// https://github.com/notaryproject/notaryproject/blob/main/specs/signature-specification.md#algorithm-selection
const (
	HashAlgorithmSHA256 HashAlgorithm = "SHA-256"
	HashAlgorithmSHA384 HashAlgorithm = "SHA-384"
	HashAlgorithmSHA512 HashAlgorithm = "SHA-512"
)

// HashAlgorithmFromKeySpec returns the name of hash function according to the spec.
func HashAlgorithmFromKeySpec(k signature.KeySpec) (HashAlgorithm, error) {
	switch k.Type {
	case signature.KeyTypeEC:
		switch k.Size {
		case 256:
			return HashAlgorithmSHA256, nil
		case 384:
			return HashAlgorithmSHA384, nil
		case 521:
			return HashAlgorithmSHA512, nil
		}
	case signature.KeyTypeRSA:
		switch k.Size {
		case 2048:
			return HashAlgorithmSHA256, nil
		case 3072:
			return HashAlgorithmSHA384, nil
		case 4096:
			return HashAlgorithmSHA512, nil
		}
	}
	return "", fmt.Errorf("invalid KeySpec %q", k)
}

// SignatureAlgorithm is the type of signature algorithm
type SignatureAlgorithm string

// one of the following supported signing algorithm names.
//
// https://github.com/notaryproject/notaryproject/blob/main/specs/signature-specification.md#algorithm-selection
const (
	SignatureAlgorithmECDSA_SHA256      SignatureAlgorithm = "ECDSA-SHA-256"
	SignatureAlgorithmECDSA_SHA384      SignatureAlgorithm = "ECDSA-SHA-384"
	SignatureAlgorithmECDSA_SHA512      SignatureAlgorithm = "ECDSA-SHA-512"
	SignatureAlgorithmRSASSA_PSS_SHA256 SignatureAlgorithm = "RSASSA-PSS-SHA-256"
	SignatureAlgorithmRSASSA_PSS_SHA384 SignatureAlgorithm = "RSASSA-PSS-SHA-384"
	SignatureAlgorithmRSASSA_PSS_SHA512 SignatureAlgorithm = "RSASSA-PSS-SHA-512"
)

// EncodeSigningAlgorithm returns the signing algorithm name of an algorithm
// according to the spec.
func EncodeSigningAlgorithm(alg signature.Algorithm) (SignatureAlgorithm, error) {
	switch alg {
	case signature.AlgorithmES256:
		return SignatureAlgorithmECDSA_SHA256, nil
	case signature.AlgorithmES384:
		return SignatureAlgorithmECDSA_SHA384, nil
	case signature.AlgorithmES512:
		return SignatureAlgorithmECDSA_SHA512, nil
	case signature.AlgorithmPS256:
		return SignatureAlgorithmRSASSA_PSS_SHA256, nil
	case signature.AlgorithmPS384:
		return SignatureAlgorithmRSASSA_PSS_SHA384, nil
	case signature.AlgorithmPS512:
		return SignatureAlgorithmRSASSA_PSS_SHA512, nil
	}
	return "", fmt.Errorf("invalid algorithm %q", alg)
}

// DecodeSigningAlgorithm parses the signing algorithm name from a given string.
func DecodeSigningAlgorithm(raw SignatureAlgorithm) (signature.Algorithm, error) {
	switch raw {
	case SignatureAlgorithmECDSA_SHA256:
		return signature.AlgorithmES256, nil
	case SignatureAlgorithmECDSA_SHA384:
		return signature.AlgorithmES384, nil
	case SignatureAlgorithmECDSA_SHA512:
		return signature.AlgorithmES512, nil
	case SignatureAlgorithmRSASSA_PSS_SHA256:
		return signature.AlgorithmPS256, nil
	case SignatureAlgorithmRSASSA_PSS_SHA384:
		return signature.AlgorithmPS384, nil
	case SignatureAlgorithmRSASSA_PSS_SHA512:
		return signature.AlgorithmPS512, nil
	}
	return 0, errors.New("unknown signing algorithm")
}
