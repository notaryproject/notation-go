package signature

import (
	"errors"

	"github.com/notaryproject/notation-core-go/signature"
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
