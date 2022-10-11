package signature

import (
	"github.com/notaryproject/notation-core-go/signature"
)

// RegisteredEnvelopeTypes lists registered envelope media types.
func RegisteredEnvelopeTypes() []string {
	return signature.RegisteredEnvelopeTypes()
}
