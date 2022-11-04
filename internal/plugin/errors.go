package plugin

import (
	"encoding/json"
	"errors"
	"fmt"
)

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

func (e RequestError) Is(target error) bool {
	if et, ok := target.(RequestError); ok {
		if e.Code != et.Code {
			return false
		}
		if e.Err == et.Err {
			return true
		}
		return e.Err != nil && et.Err != nil && e.Err.Error() == et.Err.Error()
	}
	return false
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
	*e = RequestError{Code: tmp.Code, Metadata: tmp.Metadata}
	if tmp.Message != "" {
		e.Err = errors.New(tmp.Message)
	}
	return nil
}
