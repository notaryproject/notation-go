// Package hashutil provides utilities for hash.
package hashutil

import "crypto"

// ComputeHash computes the digest of the message with the given hash algorithm.
// Callers should check the availability of the hash algorithm before invoking.
func ComputeHash(hash crypto.Hash, message []byte) ([]byte, error) {
	h := hash.New()
	_, err := h.Write(message)
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
