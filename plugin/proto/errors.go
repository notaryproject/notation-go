// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proto

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
