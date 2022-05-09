package verification

// X509TrustStore
type X509TrustStore struct {
	certificates []Certificate
}

func (x X509TrustStore) validate() {

}

func LoadX509TrustStore(path string) TrustStore {
	// read path
	// throw errof if it is a symlink
	// throw error if there are sub-directories
	// throw error if a file is symlink
	// read cert files if not DER or PEM
	// return trust store object
}
