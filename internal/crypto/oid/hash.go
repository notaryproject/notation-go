package oid

import (
	"crypto"
	"encoding/asn1"
)

// ConvertToHash converts ASN.1 digest algorithm identifier to golang crypto hash
// if it is available.
func ConvertToHash(alg asn1.ObjectIdentifier) (crypto.Hash, bool) {
	var hash crypto.Hash
	switch {
	case SHA1.Equal(alg):
		hash = crypto.SHA1
	case SHA256.Equal(alg):
		hash = crypto.SHA256
	case SHA384.Equal(alg):
		hash = crypto.SHA384
	case SHA512.Equal(alg):
		hash = crypto.SHA512
	default:
		return hash, false
	}
	return hash, hash.Available()
}
