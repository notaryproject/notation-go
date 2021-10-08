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
// WARNING: This media type is in a **TBD** state, and is subject to change.
const MediaTypeNotationPayload = "application/vnd.cncf.notary.signature.v2.payload+json"

// payload contains the subject manifest and other attributes that have to be integrity
// protected.
type payload struct {
	Notation notationClaim `json:"notary.v2"`
	jwt.RegisteredClaims
}

// notationClaim is the top level node and private claim, encapsulating the notary v2 data.
type notationClaim struct {
	SubjectManifest  notation.Descriptor `json:"subjectManifest"`
	SignedAttributes signedAttributes    `json:"signedAttrs,omitempty"`
}

// signedAttributes contains additional attributes that needs to be integrity protected.
type signedAttributes struct {
	Reserved map[string]interface{} `json:"reserved,omitempty"`
	Custom   map[string]interface{} `json:"custom,omitempty"`
}

// packPayload generates JWS payload according the signing content and options.
func packPayload(desc notation.Descriptor, opts notation.SignOptions) *payload {
	var reservedAttributes map[string]interface{}
	if identity := opts.Metadata.Identity; identity != "" {
		reservedAttributes = map[string]interface{}{
			"identity": identity,
		}
	}
	var expiresAt *jwt.NumericDate
	if !opts.Expiry.IsZero() {
		expiresAt = jwt.NewNumericDate(opts.Expiry)
	}
	return &payload{
		Notation: notationClaim{
			SubjectManifest: desc,
			SignedAttributes: signedAttributes{
				Reserved: reservedAttributes,
				Custom:   opts.Metadata.Attributes,
			},
		},
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: expiresAt,
		},
	}
}
