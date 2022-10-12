package signature

import (
	"github.com/notaryproject/notation-core-go/signature"
)

// Envelope provides basic functions to manipulate signatures.
type Envelope = signature.Envelope

// RegisteredEnvelopeTypes lists registered envelope media types.
func RegisteredEnvelopeTypes() []string {
	return signature.RegisteredEnvelopeTypes()
}

// ParseEnvelope generates an envelope for given envelope bytes with specified
// media type.
func ParseEnvelope(mediaType string, envelopeBytes []byte) (Envelope, error) {
	return signature.ParseEnvelope(mediaType, envelopeBytes)
}
