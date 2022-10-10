package verification

import (
	"crypto/x509"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	corex509 "github.com/notaryproject/notation-core-go/x509"
)

// X509TrustStore provide the members and behavior for a named trust store
type X509TrustStore struct {
	Name         string
	Prefix       string
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
		certs, err := corex509.ReadCertificateFile(joinedPath)
		if err != nil {
			return nil, fmt.Errorf("error while reading certificates from %q: %w", joinedPath, err)
		}

		if err := validateCerts(certs, joinedPath); err != nil {
			return nil, err
		}

		trustStore.Certificates = append(trustStore.Certificates, certs...)
	}

	if len(trustStore.Certificates) < 1 {
		return nil, fmt.Errorf("trust store %q has no x509 certificates", path)
	}

	trustStore.Name = filepath.Base(path)
	trustStore.Prefix = filepath.Base(filepath.Dir(path))
	trustStore.Path = path

	return &trustStore, nil
}

func validateCerts(certs []*x509.Certificate, path string) error {
	// to prevent any trust store misconfigurations, ensure there is at least
	// one certificate from each file.
	if len(certs) < 1 {
		return fmt.Errorf("could not parse a certificate from %q, every file in a trust store must have a PEM or DER certificate in it", path)
	}

	// for each and every cert in certs, it needs to be a CA or self-signed
	// certificate to pass the validation.
	for _, cert := range certs {
		if !cert.IsCA {
			if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
				return fmt.Errorf(
					"certificate with subject %q from file %q is not a CA or self-signed certificate",
					cert.Subject,
					path,
				)
			}
		}
	}

	return nil
}
