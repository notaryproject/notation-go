package notation

//
type ErrorPushSignatureFailed struct {
	Msg string
}

func (e ErrorPushSignatureFailed) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "failed to push signature to registry"
}

// ErrorVerificationInconclusive is used when signature verification fails due to a runtime error (e.g. a network error)
type ErrorVerificationInconclusive struct {
	Msg string
}

func (e ErrorVerificationInconclusive) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "signature verification was inclusive due to an unexpected error"
}

// ErrorNoApplicableTrustPolicy is used when there is no trust policy that applies to the given artifact
type ErrorNoApplicableTrustPolicy struct {
	Msg string
}

func (e ErrorNoApplicableTrustPolicy) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "there is no applicable trust policy for the given artifact"
}

// ErrorSignatureRetrievalFailed is used when notation is unable to retrieve the digital signature/s for the given artifact
type ErrorSignatureRetrievalFailed struct {
	Msg string
}

func (e ErrorSignatureRetrievalFailed) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "unable to retrieve the digital signature from the registry"
}

// ErrorVerificationFailed is used when it is determined that the digital signature/s is not valid for the given artifact
type ErrorVerificationFailed struct {
	Msg string
}

func (e ErrorVerificationFailed) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "signature verification failed"
}
