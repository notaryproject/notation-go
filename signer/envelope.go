package signer

import (
	"fmt"

	"github.com/notaryproject/notation-core-go/signature"
)

// validatePayloadContentType validates signature payload's content type.
func ValidatePayloadContentType(payload *signature.Payload) error {
	switch payload.ContentType {
	case mediaTypePayloadV1:
		return nil
	default:
		return fmt.Errorf("payload content type %q not supported", payload.ContentType)
	}
}
