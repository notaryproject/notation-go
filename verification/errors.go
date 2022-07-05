package verification

// ErrorVerificationInconclusive is used when signature verification fails due to a runtime error (e.g. a network error)
type ErrorVerificationInconclusive struct {
	msg string
}

func (e ErrorVerificationInconclusive) Error() string {
	if e.msg != "" {
		return e.msg
	}
	return "signature verification was inclusive due to an unexpected error"
}

// ErrorNoApplicableTrustPolicy is used when there is no trust policy that applies to the given artifact
type ErrorNoApplicableTrustPolicy struct {
	msg string
}

func (e ErrorNoApplicableTrustPolicy) Error() string {
	if e.msg != "" {
		return e.msg
	}
	return "there is no applicable trust policy for the given artifact"
}

// ErrorSignatureRetrievalFailed is used when notation is unable to retrieve the digital signature/s for the given artifact
type ErrorSignatureRetrievalFailed struct {
	msg string
}

func (e ErrorSignatureRetrievalFailed) Error() string {
	if e.msg != "" {
		return e.msg
	}
	return "unable to retrieve the digital signature from the registry"
}

// ErrorVerificationFailed is used when it is determined that the digital signature/s is not valid for the given artifact
type ErrorVerificationFailed struct {
	msg string
}

func (e ErrorVerificationFailed) Error() string {
	if e.msg != "" {
		return e.msg
	}
	return "signature verification failed"
}
