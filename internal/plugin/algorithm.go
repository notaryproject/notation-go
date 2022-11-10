package plugin

import (
	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go/plugin/proto"
)

// one of the following supported key spec names.
//
// https://github.com/notaryproject/notaryproject/blob/main/signature-specification.md#algorithm-selection
const (
	RSA_2048 = string(proto.KeySpecRSA2048)
	RSA_3072 = string(proto.KeySpecRSA3072)
	RSA_4096 = string(proto.KeySpecRSA4096)
	EC_256   = string(proto.KeySpecEC256)
	EC_384   = string(proto.KeySpecEC384)
	EC_521   = string(proto.KeySpecEC521)
)

// one of the following supported hash algorithm names.
//
// https://github.com/notaryproject/notaryproject/blob/main/signature-specification.md#algorithm-selection
const (
	SHA_256 = string(proto.HashAlgorithmSHA256)
	SHA_384 = string(proto.HashAlgorithmSHA384)
	SHA_512 = string(proto.HashAlgorithmSHA512)
)

// one of the following supported signing algorithm names.
//
// https://github.com/notaryproject/notaryproject/blob/main/signature-specification.md#algorithm-selection
const (
	ECDSA_SHA_256      = string(proto.SignatureAlgorithmECDSA_SHA256)
	ECDSA_SHA_384      = string(proto.SignatureAlgorithmECDSA_SHA384)
	ECDSA_SHA_512      = string(proto.SignatureAlgorithmECDSA_SHA512)
	RSASSA_PSS_SHA_256 = string(proto.SignatureAlgorithmRSASSA_PSS_SHA256)
	RSASSA_PSS_SHA_384 = string(proto.SignatureAlgorithmRSASSA_PSS_SHA384)
	RSASSA_PSS_SHA_512 = string(proto.SignatureAlgorithmRSASSA_PSS_SHA512)
)

// KeySpecName returns the name of a keySpec according to the spec.
func KeySpecString(k signature.KeySpec) string {
	ks, _ := proto.EncodeKeySpec(k)
	return string(ks)
}

// KeySpecHashName returns the name of hash function according to the spec.
func KeySpecHashString(k signature.KeySpec) string {
	hashAlg, _ := proto.HashAlgorithmFromKeySpec(k)
	return string(hashAlg)
}

// ParseKeySpecFromName parses keySpec name to a signature.keySpec type.
func ParseKeySpec(raw string) (keySpec signature.KeySpec, err error) {
	return proto.DecodeKeySpec(proto.KeySpec(raw))
}

// SigningAlgorithmName returns the signing algorithm name of an algorithm according to the spec.
func SigningAlgorithmString(alg signature.Algorithm) string {
	sigAlg, _ := proto.EncodeSigningAlgorithm(alg)
	return string(sigAlg)
}

// ParseSigningAlgorithFromName parses the signing algorithm name from a given string.
func ParseSigningAlgorithm(raw string) (signature.Algorithm, error) {
	return proto.DecodeSigningAlgorithm(proto.SignatureAlgorithm(raw))
}
