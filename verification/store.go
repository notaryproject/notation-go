package verification

import (
	"crypto/x509"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/notaryproject/notation-go/crypto/cryptoutil"
)

// X509TrustStore provide the members and behavior for a named trust store
type X509TrustStore struct {
	Name         string
	Path         string
	Certificates []*x509.Certificate
}

// LoadX509TrustStore loads a named trust store from a certificates directory,
// throws error if parsing a certificate from a file fails
func LoadX509TrustStore(path string) (*X509TrustStore, error) {
	// check path is valid
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("%q does not exist", path)
	}

	// throw error if path is not a directory or is a symlink
	fileInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	mode := fileInfo.Mode()
	if !mode.IsDir() || mode&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("%q is not a regular directory (symlinks are not supported)", path)
	}

	files, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}

	var trustStore X509TrustStore
	for _, file := range files {
		joinedPath := filepath.Join(path, file.Name())
		if file.IsDir() || file.Type()&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("%q is not a regular file (directories or symlinks are not supported)", joinedPath)
		}
		certs, err := cryptoutil.ReadCertificateFile(joinedPath) // TODO support DER formatted files
		if err != nil {
			return nil, err
		}

		// to prevent any trust store misconfigurations, ensure there is at least one certificate from each file
		if len(certs) < 1 {
			return nil, fmt.Errorf("could not parse a certificate from %q, every file in a trust store must have a PEM or DER certificate in it", joinedPath)
		}
		trustStore.Certificates = append(trustStore.Certificates, certs...)
	}

	trustStore.Name = filepath.Base(path)
	trustStore.Path = path

	return &trustStore, nil
}
