package signature

import (
	"errors"
	"fmt"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go"
)

// ValidateEnvelopeMediaType validetes envelope media type is supported by notation-core-go.
func ValidateEnvelopeMediaType(mediaType string) error {
	for _, types := range signature.RegisteredEnvelopeTypes() {
		if mediaType == types {
			return nil
		}
	}
	return errors.New("invalid envelope media type")
}

// ValidatePayloadContentType validates signature payload's content type.
func ValidatePayloadContentType(payload *signature.Payload) error {
	switch payload.ContentType {
	case notation.MediaTypePayloadV1:
		return nil
	default:
		return fmt.Errorf("payload content type %q not supported", payload.ContentType)
	}
}
