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

package notation

// ErrorPushSignatureFailed is used when failed to push signature to the
// target registry.
//
// Deprecated: Use PushSignatureFailedError instead.
type ErrorPushSignatureFailed struct {
	Msg string
}

func (e ErrorPushSignatureFailed) Error() string {
	if e.Msg != "" {
		return "failed to push signature to registry with error: " + e.Msg
	}
	return "failed to push signature to registry"
}

// PushSignatureFailedError is used when failed to push signature to the
// target registry.
type PushSignatureFailedError struct {
	Msg string
}

func (e PushSignatureFailedError) Error() string {
	if e.Msg != "" {
		return "failed to push signature to registry with error: " + e.Msg
	}
	return "failed to push signature to registry"
}

// ErrorVerificationInconclusive is used when signature verification fails due
// to a runtime error (e.g. a network error)
//
// Deprecated: Use VerificationInconclusiveError instead.
type ErrorVerificationInconclusive struct {
	Msg string
}

func (e ErrorVerificationInconclusive) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "signature verification was inclusive due to an unexpected error"
}

// VerificationInconclusiveError is used when signature verification fails due
// to a runtime error (e.g. a network error)
type VerificationInconclusiveError struct {
	Msg string
}

func (e VerificationInconclusiveError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "signature verification was inclusive due to an unexpected error"
}

// ErrorNoApplicableTrustPolicy is used when there is no trust policy that
// applies to the given artifact
//
// Deprecated: Use NoApplicableTrustPolicyError instead.
type ErrorNoApplicableTrustPolicy struct {
	Msg string
}

func (e ErrorNoApplicableTrustPolicy) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "there is no applicable trust policy for the given artifact"
}

// NoApplicableTrustPolicyError is used when there is no trust policy that
// applies to the given artifact
type NoApplicableTrustPolicyError struct {
	Msg string
}

func (e NoApplicableTrustPolicyError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "there is no applicable trust policy for the given artifact"
}

// ErrorSignatureRetrievalFailed is used when notation is unable to retrieve the
// digital signature/s for the given artifact
//
// Deprecated: Use SignatureRetrievalFailedError instead.
type ErrorSignatureRetrievalFailed struct {
	Msg string
}

func (e ErrorSignatureRetrievalFailed) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "unable to retrieve the digital signature from the registry"
}

// SignatureRetrievalFailedError is used when notation is unable to retrieve the
// digital signature/s for the given artifact
type SignatureRetrievalFailedError struct {
	Msg string
}

func (e SignatureRetrievalFailedError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "unable to retrieve the digital signature from the registry"
}

// ErrorVerificationFailed is used when it is determined that the digital
// signature/s is not valid for the given artifact
//
// Deprecated: Use VerificationFailedError instead.
type ErrorVerificationFailed struct {
	Msg string
}

func (e ErrorVerificationFailed) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "signature verification failed"
}

// VerificationFailedError is used when it is determined that the digital
// signature/s is not valid for the given artifact
type VerificationFailedError struct {
	Msg string
}

func (e VerificationFailedError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "signature verification failed"
}

// ErrorUserMetadataVerificationFailed is used when the signature does not
// contain the user specified metadata
//
// Deprecated: Use UserMetadataVerificationFailedError instead.
type ErrorUserMetadataVerificationFailed struct {
	Msg string
}

func (e ErrorUserMetadataVerificationFailed) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "unable to find specified metadata in the signature"
}

// UserMetadataVerificationFailedError is used when the signature does not
// contain the user specified metadata
type UserMetadataVerificationFailedError struct {
	Msg string
}

func (e UserMetadataVerificationFailedError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "unable to find specified metadata in the signature"
}
