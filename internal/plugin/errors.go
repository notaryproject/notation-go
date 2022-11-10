package plugin

import (
	"github.com/notaryproject/notation-go/plugin/proto"
)

type ErrorCode = proto.ErrorCode

const (
	// Any of the required request fields was empty,
	// or a value was malformed/invalid.
	ErrorCodeValidation ErrorCode = proto.ErrorCodeValidation

	// The contract version used in the request is unsupported.
	ErrorCodeUnsupportedContractVersion ErrorCode = proto.ErrorCodeUnsupportedContractVersion

	// Authentication/authorization error to use given key.
	ErrorCodeAccessDenied ErrorCode = proto.ErrorCodeAccessDenied

	// The operation to generate signature timed out
	// and can be retried by Notation.
	ErrorCodeTimeout ErrorCode = proto.ErrorCodeTimeout

	// The operation to generate signature was throttles
	// and can be retried by Notation.
	ErrorCodeThrottled ErrorCode = proto.ErrorCodeThrottled

	// Any general error that does not fall into any categories.
	ErrorCodeGeneric ErrorCode = proto.ErrorCodeGeneric
)

type jsonErr struct {
	Code     ErrorCode         `json:"errorCode"`
	Message  string            `json:"errorMessage,omitempty"`
	Metadata map[string]string `json:"errorMetadata,omitempty"`
}

// RequestError is the common error response for any request.
type RequestError = proto.RequestError
