package verification

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	corex509 "github.com/notaryproject/notation-core-go/x509"
	"github.com/notaryproject/notation-go/dir"
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

		// to prevent any trust store misconfigurations, ensure there is at least one certificate from each file
		if len(certs) < 1 {
			return nil, fmt.Errorf("could not parse a certificate from %q, every file in a trust store must have a PEM or DER certificate in it", joinedPath)
		}
		for _, cert := range certs {
			if !cert.IsCA {
				return nil, fmt.Errorf("certificate with subject %q from file %q is not a CA certificate, only CA certificates (BasicConstraint CA=True) are allowed", cert.Subject, joinedPath)
			}
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

// AddCertToTrustStore adds a single cert file at path to the User level trust store
// under dir truststore/x509/storeType/namedStore
func AddCertToTrustStore(path, storeType, namedStore string) error {
	// initialize
	certPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	storeType = strings.TrimSpace(storeType)
	if storeType == "" {
		return errors.New("store type cannot be empty or contain only whitespaces")
	}
	namedStore = strings.TrimSpace(namedStore)
	if namedStore == "" {
		return errors.New("named store cannot be empty or contain only whitespaces")
	}

	// check if the target path is a cert (support PEM and DER formats)
	if _, err := corex509.ReadCertificateFile(certPath); err != nil {
		return err
	}

	// core process
	// get User level trust store path
	trustStorePath, err := dir.Path.UserConfigFS.GetPath(dir.TrustStoreDir, "x509", storeType, namedStore)
	if err := checkError(err); err != nil {
		return err
	}
	// check if certificate already in the trust store
	if _, err := os.Stat(filepath.Join(trustStorePath, filepath.Base(certPath))); err == nil {
		return errors.New("certificate already exists in the Trust Store")
	}
	// add cert to trust store
	_, err = copy(certPath, trustStorePath)
	if err != nil {
		return err
	}

	return nil
}
