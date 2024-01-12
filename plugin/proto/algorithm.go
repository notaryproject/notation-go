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
	"errors"
	"fmt"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-plugin-framework-go/plugin"
)

// KeySpec is type of the signing algorithm, including algorithm and size.
type KeySpec = plugin.KeySpec

// one of the following supported key spec names.
//
// https://github.com/notaryproject/notaryproject/blob/main/specs/signature-specification.md#algorithm-selection
const (
	KeySpecRSA2048 = plugin.KeySpecRSA2048
	KeySpecRSA3072 = plugin.KeySpecRSA3072
	KeySpecRSA4096 = plugin.KeySpecRSA4096
	KeySpecEC256   = plugin.KeySpecEC256
	KeySpecEC384   = plugin.KeySpecEC384
	KeySpecEC521   = plugin.KeySpecEC521
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
type HashAlgorithm = plugin.HashAlgorithm

// one of the following supported hash algorithm names.
//
// https://github.com/notaryproject/notaryproject/blob/main/specs/signature-specification.md#algorithm-selection
const (
	HashAlgorithmSHA256 = plugin.HashAlgorithmSHA256
	HashAlgorithmSHA384 = plugin.HashAlgorithmSHA384
	HashAlgorithmSHA512 = plugin.HashAlgorithmSHA512
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
type SignatureAlgorithm = plugin.SignatureAlgorithm

// one of the following supported signing algorithm names.
//
// https://github.com/notaryproject/notaryproject/blob/main/specs/signature-specification.md#algorithm-selection
const (
	SignatureAlgorithmECDSA_SHA256      = plugin.SignatureAlgorithmECDSA_SHA256
	SignatureAlgorithmECDSA_SHA384      = plugin.SignatureAlgorithmECDSA_SHA384
	SignatureAlgorithmECDSA_SHA512      = plugin.SignatureAlgorithmECDSA_SHA512
	SignatureAlgorithmRSASSA_PSS_SHA256 = plugin.SignatureAlgorithmRSASSA_PSS_SHA256
	SignatureAlgorithmRSASSA_PSS_SHA384 = plugin.SignatureAlgorithmRSASSA_PSS_SHA384
	SignatureAlgorithmRSASSA_PSS_SHA512 = plugin.SignatureAlgorithmRSASSA_PSS_SHA512
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
