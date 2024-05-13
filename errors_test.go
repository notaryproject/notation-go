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
