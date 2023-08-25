package truststore

// ErrorTrustStore is used when accessing specified trust store failed
type ErrorTrustStore struct {
	WrappedError error
}

func (e ErrorTrustStore) Error() string {
	if e.WrappedError != nil {
		return e.WrappedError.Error()
	}
	return "unable to access the trust store"
}

// ErrorCertificate is used when reading a certificate failed
type ErrorCertificate struct {
	WrappedError error
}

func (e ErrorCertificate) Error() string {
	if e.WrappedError != nil {
		return e.WrappedError.Error()
	}
	return "unable to read the certificate"
}

// ErrorNonExistence is used when specified trust store or
// certificate path does not exist.
type ErrorNonExistence struct {
	WrappedError error
}

func (e ErrorNonExistence) Error() string {
	if e.WrappedError != nil {
		return e.WrappedError.Error()
	}
	return "unable to find specified trust store or certificate"
}
