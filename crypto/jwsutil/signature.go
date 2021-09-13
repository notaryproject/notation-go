// Package jwsutil provides serialization utilities for JWT libraries.
package jwsutil

import (
	"encoding/json"
	"strings"
)

// Signature represents a detached signature.
type Signature struct {
	Protected   string          `json:"protected,omitempty"`
	Unprotected json.RawMessage `json:"header,omitempty"`
	Signature   string          `json:"signature,omitempty"`
}

// CompleteSignature represents a clear signed signature.
type CompleteSignature struct {
	Payload string `json:"payload,omitempty"`
	Signature
}

// Parse parses the compact serialized JWS.
// See https://www.rfc-editor.org/rfc/rfc7515#section-7.1
func ParseCompact(serialized string) (CompleteSignature, error) {
	parts := strings.Split(serialized, ".")
	if len(parts) != 3 {
		return CompleteSignature{}, ErrInvalidCompactSerialization
	}
	return CompleteSignature{
		Payload: parts[1],
		Signature: Signature{
			Protected: parts[0],
			Signature: parts[2],
		},
	}, nil
}

// SerializeCompact serialize the signature in JWS Compact Serialization
// See https://www.rfc-editor.org/rfc/rfc7515#section-7.1
func (s CompleteSignature) SerializeCompact() string {
	return strings.Join([]string{s.Protected, s.Payload, s.Signature.Signature}, ".")
}

// Enclose packs the signature into an envelope.
func (s CompleteSignature) Enclose() Envelope {
	return Envelope{
		Payload: s.Payload,
		Signatures: []Signature{
			s.Signature,
		},
	}
}
