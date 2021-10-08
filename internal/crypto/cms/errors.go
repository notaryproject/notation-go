package cms

import "errors"

// ErrExpectSignedData is returned if wrong content is provided when signed
// data is expected.
var ErrExpectSignedData = errors.New("cms: signed data expected")

// ErrAttributeNotFound is returned if attribute is not found in a given set.
var ErrAttributeNotFound = errors.New("attribute not found")

// Verification errors
var (
	ErrSignerNotFound      = VerificationError{Message: "signer not found"}
	ErrCertificateNotFound = VerificationError{Message: "certificate not found"}
)

// SyntaxError indicates that the ASN.1 data is invalid.
type SyntaxError struct {
	Message string
	Detail  error
}

// Error returns error message.
func (e SyntaxError) Error() string {
	msg := "cms: syntax error"
	if e.Message != "" {
		msg += ": " + e.Message
	}
	if e.Detail != nil {
		msg += ": " + e.Detail.Error()
	}
	return msg
}

// Unwrap returns the internal error.
func (e SyntaxError) Unwrap() error {
	return e.Detail
}

// VerificationError indicates verification failures.
type VerificationError struct {
	Message string
	Detail  error
}

// Error returns error message.
func (e VerificationError) Error() string {
	msg := "cms: verification failure"
	if e.Message != "" {
		msg += ": " + e.Message
	}
	if e.Detail != nil {
		msg += ": " + e.Detail.Error()
	}
	return msg
}

// Unwrap returns the internal error.
func (e VerificationError) Unwrap() error {
	return e.Detail
}
