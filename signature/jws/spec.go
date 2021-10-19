// Package jws signs and verifies artifacts with signatures in JWS format.
// The specification is currently underdiscussion and is not yet finalized.
// Reference: https://github.com/notaryproject/notaryproject/pull/93
package jws

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/notaryproject/notation-go-lib"
)

// unprotectedHeader contains the header parameters that are not integrity protected.
type unprotectedHeader struct {
	TimeStampToken []byte   `json:"timestamp,omitempty"`
	CertChain      [][]byte `json:"x5c,omitempty"`
}

// MediaTypeNotationPayload describes the media type of the payload of notation signature.
const MediaTypeNotationPayload = "application/vnd.cncf.notary.v2.jws.v1"

// payload contains the subject manifest and other attributes that have to be integrity
// protected.
type payload struct {
	Notation notationClaim `json:"notary"`
	jwt.RegisteredClaims
}

// notationClaim is the top level node and private claim, encapsulating the notary v2 data.
type notationClaim struct {
	Subject notation.Descriptor `json:"subject"`
}

// packPayload generates JWS payload according the signing content and options.
func packPayload(desc notation.Descriptor, opts notation.SignOptions) *payload {
	var expiresAt *jwt.NumericDate
	if !opts.Expiry.IsZero() {
		expiresAt = jwt.NewNumericDate(opts.Expiry)
	}
	return &payload{
		Notation: notationClaim{
			Subject: desc,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: expiresAt,
		},
	}
}
