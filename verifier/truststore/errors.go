package truststore

// ErrorTrustStoreNonExistence is used when specified trust store or
// certificate path does not exist.
type ErrorTrustStoreNonExistence struct {
	Msg string
}

func (e ErrorTrustStoreNonExistence) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "unable to find specified trust store or certificate"
}
