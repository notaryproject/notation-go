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

import "testing"

func TestErrorMessages(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "ErrorPushSignatureFailed with message",
			err:  ErrorPushSignatureFailed{Msg: "test message"},
			want: "failed to push signature to registry with error: test message",
		},
		{
			name: "ErrorPushSignatureFailed without message",
			err:  ErrorPushSignatureFailed{},
			want: "failed to push signature to registry",
		},
		{
			name: "ErrorVerificationInconclusive with message",
			err:  ErrorVerificationInconclusive{Msg: "test message"},
			want: "test message",
		},
		{
			name: "ErrorVerificationInconclusive without message",
			err:  ErrorVerificationInconclusive{},
			want: "signature verification was inclusive due to an unexpected error",
		},
		{
			name: "ErrorNoApplicableTrustPolicy with message",
			err:  ErrorNoApplicableTrustPolicy{Msg: "test message"},
			want: "test message",
		},
		{
			name: "ErrorNoApplicableTrustPolicy without message",
			err:  ErrorNoApplicableTrustPolicy{},
			want: "there is no applicable trust policy for the given artifact",
		},
		{
			name: "ErrorSignatureRetrievalFailed with message",
			err:  ErrorSignatureRetrievalFailed{Msg: "test message"},
			want: "test message",
		},
		{
			name: "ErrorSignatureRetrievalFailed without message",
			err:  ErrorSignatureRetrievalFailed{},
			want: "unable to retrieve the digital signature from the registry",
		},
		{
			name: "ErrorVerificationFailed with message",
			err:  ErrorVerificationFailed{Msg: "test message"},
			want: "test message",
		},
		{
			name: "ErrorVerificationFailed without message",
			err:  ErrorVerificationFailed{},
			want: "signature verification failed",
		},
		{
			name: "ErrorUserMetadataVerificationFailed with message",
			err:  ErrorUserMetadataVerificationFailed{Msg: "test message"},
			want: "test message",
		},
		{
			name: "ErrorUserMetadataVerificationFailed without message",
			err:  ErrorUserMetadataVerificationFailed{},
			want: "unable to find specified metadata in the signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCustomErrorPrintsCorrectMessage(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "PushSignatureFailedError with message",
			err:  PushSignatureFailedError{Msg: "test message"},
			want: "failed to push signature to registry with error: test message",
		},
		{
			name: "PushSignatureFailedError without message",
			err:  PushSignatureFailedError{},
			want: "failed to push signature to registry",
		},
		{
			name: "VerificationInconclusiveError with message",
			err:  VerificationInconclusiveError{Msg: "test message"},
			want: "test message",
		},
		{
			name: "VerificationInconclusiveError without message",
			err:  VerificationInconclusiveError{},
			want: "signature verification was inclusive due to an unexpected error",
		},
		{
			name: "NoApplicableTrustPolicyError with message",
			err:  NoApplicableTrustPolicyError{Msg: "test message"},
			want: "test message",
		},
		{
			name: "NoApplicableTrustPolicyError without message",
			err:  NoApplicableTrustPolicyError{},
			want: "there is no applicable trust policy for the given artifact",
		},
		{
			name: "SignatureRetrievalFailedError with message",
			err:  SignatureRetrievalFailedError{Msg: "test message"},
			want: "test message",
		},
		{
			name: "SignatureRetrievalFailedError without message",
			err:  SignatureRetrievalFailedError{},
			want: "unable to retrieve the digital signature from the registry",
		},
		{
			name: "VerificationFailedError with message",
			err:  VerificationFailedError{Msg: "test message"},
			want: "test message",
		},
		{
			name: "VerificationFailedError without message",
			err:  VerificationFailedError{},
			want: "signature verification failed",
		},
		{
			name: "UserMetadataVerificationFailedError with message",
			err:  UserMetadataVerificationFailedError{Msg: "test message"},
			want: "test message",
		},
		{
			name: "UserMetadataVerificationFailedError without message",
			err:  UserMetadataVerificationFailedError{},
			want: "unable to find specified metadata in the signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %v, want %v", got, tt.want)
			}
		})
	}
}
