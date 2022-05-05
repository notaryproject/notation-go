package signature

const (
	// MediaTypeJWSEnvelope describes the media type of the JWS envelope.
	MediaTypeJWSEnvelope = "application/vnd.cncf.notary.v2.jws.v1"
)

// JWSNotaryClaim is a Notary private claim.
type JWSNotaryClaim struct {
	Subject Descriptor `json:"subject"`
}

// JWSPayload contains the set of claims used by Notary V2.
type JWSPayload struct {
	// Private claim.
	Notary JWSNotaryClaim `json:"notary"`

	// Identifies the number of seconds since Epoch at which the signature was issued.
	IssuedAt int64 `json:"iat"`

	// Identifies the number of seconds since Epoch at which the signature must not be considered valid.
	ExpiresAt int64 `json:"exp,omitempty"`
}

// JWSProtectedHeader contains the set of protected headers.
type JWSProtectedHeader struct {
	// Defines which algorithm was used to generate the signature.
	Algorithm string `json:"alg"`

	// Media type of the secured content (the payload).
	ContentType string `json:"cty"`
}

// JWSUnprotectedHeader contains the set of unprotected headers.
type JWSUnprotectedHeader struct {
	// RFC3161 time stamp token Base64-encoded.
	TimeStampToken []byte `json:"timestamp,omitempty"`

	// List of X.509 certificates, each one Base64-encoded.
	CertChain [][]byte `json:"x5c"`
}

// JWSEnvelope is the final signature envelope.
type JWSEnvelope struct {
	// JWSPayload Base64URL-encoded.
	Payload string

	// JWSProtectedHeader Base64URL-encoded.
	Protected string

	// Signature metadata that is not integrity protected
	Header JWSUnprotectedHeader `json:"header,omitempty"`

	// Base64URL-encoded signature.
	Signature string
}
