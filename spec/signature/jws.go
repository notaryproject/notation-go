package signature

const (
	// MediaTypeJWSEnvelope describes the media type of the JWS envelope.
	MediaTypeJWSEnvelope = "application/vnd.cncf.notary.v2.jws.v1"
)

// JWSPayload contains the set of claims used by Notary V2.
type JWSPayload struct {
	// Private claim.
	Subject Descriptor `json:"subject"`

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

	// List of X.509 Base64-DER-encoded certificates
	// as defined at https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6.
	CertChain [][]byte `json:"x5c"`
}

// JWSEnvelope is the final signature envelope.
type JWSEnvelope struct {
	// JWSPayload Base64URL-encoded.
	Payload string `json:"payload"`

	// JWSProtectedHeader Base64URL-encoded.
	Protected string `json:"protected"`

	// Signature metadata that is not integrity protected
	Header JWSUnprotectedHeader `json:"header"`

	// Base64URL-encoded signature.
	Signature string `json:"signature"`
}

// JWS returns the JWS algorithm name.
func (s SignatureAlgorithm) JWS() string {
	switch s {
	case RSASSA_PSS_SHA_256:
		return "PS256"
	case RSASSA_PSS_SHA_384:
		return "PS384"
	case RSASSA_PSS_SHA_512:
		return "PS512"
	case ECDSA_SHA_256:
		return "ES256"
	case ECDSA_SHA_384:
		return "ES384"
	case ECDSA_SHA_512:
		return "ES512"
	}
	return ""
}

// NewSignatureAlgorithmJWS returns the algorithm associated to alg.
// It returns an empty string if alg is not supported.
func NewSignatureAlgorithmJWS(alg string) SignatureAlgorithm {
	switch alg {
	case "PS256":
		return RSASSA_PSS_SHA_256
	case "PS384":
		return RSASSA_PSS_SHA_384
	case "PS512":
		return RSASSA_PSS_SHA_512
	case "ES256":
		return ECDSA_SHA_256
	case "ES384":
		return ECDSA_SHA_384
	case "ES512":
		return ECDSA_SHA_512
	}
	return ""
}
