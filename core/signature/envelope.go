package signature

import (
	"github.com/notaryproject/notation-core-go/signature"
)

// RegisteredEnvelopeTypes lists registered envelope media types.
func RegisteredEnvelopeTypes() []string {
	return signature.RegisteredEnvelopeTypes()
}

// ParseEnvelope generates an envelope for given envelope bytes with specified
// media type.
func ParseEnvelope(mediaType string, envelopeBytes []byte) (signature.Envelope, error) {
	return signature.ParseEnvelope(mediaType, envelopeBytes)
}
