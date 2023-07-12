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
type ErrorPushSignatureFailed struct {
	Msg string
}

func (e ErrorPushSignatureFailed) Error() string {
	if e.Msg != "" {
		return "failed to push signature to registry with error: " + e.Msg
	}
	return "failed to push signature to registry"
}

// ErrorVerificationInconclusive is used when signature verification fails due
// to a runtime error (e.g. a network error)
type ErrorVerificationInconclusive struct {
	Msg string
}

func (e ErrorVerificationInconclusive) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "signature verification was inclusive due to an unexpected error"
}

// ErrorNoApplicableTrustPolicy is used when there is no trust policy that
// applies to the given artifact
type ErrorNoApplicableTrustPolicy struct {
	Msg string
}

func (e ErrorNoApplicableTrustPolicy) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "there is no applicable trust policy for the given artifact"
}

// ErrorSignatureRetrievalFailed is used when notation is unable to retrieve the
// digital signature/s for the given artifact
type ErrorSignatureRetrievalFailed struct {
	Msg string
}

func (e ErrorSignatureRetrievalFailed) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "unable to retrieve the digital signature from the registry"
}

// ErrorVerificationFailed is used when it is determined that the digital
// signature/s is not valid for the given artifact
type ErrorVerificationFailed struct {
	Msg string
}

func (e ErrorVerificationFailed) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "signature verification failed"
}

// ErrorUserMetadataVerificationFailed is used when the signature does not
// contain the user specified metadata
type ErrorUserMetadataVerificationFailed struct {
	Msg string
}

func (e ErrorUserMetadataVerificationFailed) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "unable to find specified metadata in the signature"
}
