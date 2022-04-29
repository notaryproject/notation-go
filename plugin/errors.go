package plugin

import (
	"encoding/json"
	"errors"
	"fmt"
)

var ErrUnknownCommand = errors.New("not a plugin command")

type ErrorCode string

const (
	// Any of the required request fields was empty,
	// or a value was malformed/invalid.
	ErrorCodeValidation ErrorCode = "VALIDATION_ERROR"

	// The contract version used in the request is unsupported.
	ErrorCodeUnsupportedContractVersion ErrorCode = "UNSUPPORTED_CONTRACT_VERSION"

	// Authentication/authorization error to use given key.
	ErrorCodeAccessDenied ErrorCode = "ACCESS_DENIED"

	// The operation to generate signature timed out
	// and can be retried by Notation.
	ErrorCodeTimeout ErrorCode = "TIMEOUT"

	// The operation to generate signature was throttles
	// and can be retried by Notation.
	ErrorCodeThrottled ErrorCode = "THROTTLED"

	// Any general error that does not fall into any categories.
	ErrorCodeGeneric ErrorCode = "ERROR"
)

type jsonErr struct {
	Code     ErrorCode         `json:"errorCode"`
	Message  string            `json:"errorMessage,omitempty"`
	Metadata map[string]string `json:"errorMetadata,omitempty"`
}

// RequestError is the common error response for any request.
type RequestError struct {
	Code     ErrorCode
	Err      error
	Metadata map[string]string
}

func (e RequestError) Error() string {
	return fmt.Sprintf("%s: %v", e.Code, e.Err)
}

func (e RequestError) Unwrap() error {
	return e.Err
}

func (e RequestError) MarshalJSON() ([]byte, error) {
	var msg string
	if e.Err != nil {
		msg = e.Err.Error()
	}
	return json.Marshal(jsonErr{e.Code, msg, e.Metadata})
}

func (e *RequestError) UnmarshalJSON(data []byte) error {
	var tmp jsonErr
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	if tmp.Code == "" && tmp.Message == "" && tmp.Metadata == nil {
		return errors.New("incomplete json")
	}
	*e = RequestError{tmp.Code, errors.New(tmp.Message), tmp.Metadata}
	return nil
}
