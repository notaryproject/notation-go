// Package truststore reads certificates in a trust store
package truststore

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	corex509 "github.com/notaryproject/notation-core-go/x509"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/internal/file"
	"github.com/notaryproject/notation-go/internal/slices"
)

// Type is an enum for trust store types supported such as
// "ca" and "signingAuthority"
type Type string

const (
	TypeCA               Type = "ca"
	TypeSigningAuthority Type = "signingAuthority"
)

var (
	Types = []Type{
		TypeCA,
		TypeSigningAuthority,
	}
)

// X509TrustStore provide list and get behaviors for the trust store
type X509TrustStore interface {
	// GetCertificates returns certificates under storeType/namedStore
	GetCertificates(ctx context.Context, storeType Type, namedStore string) ([]*x509.Certificate, error)
}

// NewX509TrustStore generates a new X509TrustStore
func NewX509TrustStore(trustStorefs dir.SysFS) X509TrustStore {
	return &x509TrustStore{trustStorefs}
}

// x509TrustStore implements X509TrustStore
type x509TrustStore struct {
	trustStorefs dir.SysFS
}

// GetCertificates returns certificates under storeType/namedStore
func (trustStore *x509TrustStore) GetCertificates(ctx context.Context, storeType Type, namedStore string) ([]*x509.Certificate, error) {
	if !isValidStoreType(storeType) {
		return nil, fmt.Errorf("unsupported store type: %s", storeType)
	}
	if !file.IsValidFileName(namedStore) {
		return nil, errors.New("named store name needs to follow [a-zA-Z0-9_.-]+ format")
	}
	path, err := trustStore.trustStorefs.SysPath(dir.X509TrustStoreDir(string(storeType), namedStore))
	if err != nil {
		return nil, err
	}
	// throw error if path is not a directory or is a symlink or does not exist.
	fileInfo, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%q does not exist", path)
		}
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

	var certificates []*x509.Certificate
	for _, file := range files {
		joinedPath := filepath.Join(path, file.Name())
		if file.IsDir() || file.Type()&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("%q is not a regular file (directories or symlinks are not supported)", joinedPath)
		}
		certs, err := corex509.ReadCertificateFile(joinedPath)
		if err != nil {
			return nil, fmt.Errorf("error while reading certificates from %q: %w", joinedPath, err)
		}
		if err := ValidateCertificates(certs); err != nil {
			return nil, fmt.Errorf("error while validating certificates from %q: %w", joinedPath, err)
		}
		certificates = append(certificates, certs...)
	}
	if len(certificates) < 1 {
		return nil, fmt.Errorf("trust store %q has no x509 certificates", path)
	}
	return certificates, nil
}

// ValidateCertificates ensures certificates from trust store are
// CA certificates or self-signed.
func ValidateCertificates(certs []*x509.Certificate) error {
	if len(certs) < 1 {
		return errors.New("input certs cannot be empty")
	}
	for _, cert := range certs {
		if !cert.IsCA {
			if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
				return fmt.Errorf(
					"certificate with subject %q is not a CA certificate or self-signed signing certificate",
					cert.Subject,
				)
			}
		}
	}
	return nil
}

// isValidStoreType checks if storeType is supported
func isValidStoreType(storeType Type) bool {
	return slices.Contains(Types, storeType)
}
