// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package truststore reads certificates in a trust store
package truststore

import (
	"bytes"
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
	TypeTSA              Type = "tsa"
)

var (
	Types = []Type{
		TypeCA,
		TypeSigningAuthority,
		TypeTSA,
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
		return nil, TrustStoreError{Msg: fmt.Sprintf("unsupported trust store type: %s", storeType)}
	}
	if !file.IsValidFileName(namedStore) {
		return nil, TrustStoreError{Msg: fmt.Sprintf("trust store name needs to follow [a-zA-Z0-9_.-]+ format, %s is invalid", namedStore)}
	}
	path, err := trustStore.trustStorefs.SysPath(dir.X509TrustStoreDir(string(storeType), namedStore))
	if err != nil {
		return nil, TrustStoreError{InnerError: err, Msg: fmt.Sprintf("failed to get path of trust store %s of type %s", namedStore, storeType)}
	}
	// throw error if path is not a directory or is a symlink or does not exist.
	fileInfo, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, TrustStoreError{InnerError: err, Msg: fmt.Sprintf("the trust store %q of type %q does not exist", namedStore, storeType)}
		}
		return nil, TrustStoreError{InnerError: err, Msg: fmt.Sprintf("failed to access the trust store %q of type %q", namedStore, storeType)}
	}
	mode := fileInfo.Mode()
	if !mode.IsDir() || mode&fs.ModeSymlink != 0 {
		return nil, TrustStoreError{Msg: fmt.Sprintf("the trust store %s of type %s with path %s is not a regular directory (symlinks are not supported)", namedStore, storeType, path)}
	}
	files, err := os.ReadDir(path)
	if err != nil {
		return nil, TrustStoreError{InnerError: err, Msg: fmt.Sprintf("failed to access the trust store %q of type %q", namedStore, storeType)}
	}

	var certificates []*x509.Certificate
	for _, file := range files {
		certFileName := file.Name()
		joinedPath := filepath.Join(path, certFileName)
		if file.IsDir() || file.Type()&fs.ModeSymlink != 0 {
			return nil, CertificateError{Msg: fmt.Sprintf("trusted certificate %s in trust store %s of type %s is not a regular file (directories or symlinks are not supported)", certFileName, namedStore, storeType)}
		}
		certs, err := corex509.ReadCertificateFile(joinedPath)
		if err != nil {
			return nil, CertificateError{InnerError: err, Msg: fmt.Sprintf("failed to read the trusted certificate %s in trust store %s of type %s", certFileName, namedStore, storeType)}
		}
		if err := ValidateCertificates(certs); err != nil {
			return nil, CertificateError{InnerError: err, Msg: fmt.Sprintf("failed to validate the trusted certificate %s in trust store %s of type %s", certFileName, namedStore, storeType)}
		}
		// we require TSA certificates in trust store to be root CA certificates
		if storeType == TypeTSA {
			for _, cert := range certs {
				if err := isRootCACertificate(cert); err != nil {
					return nil, CertificateError{InnerError: err, Msg: fmt.Sprintf("trusted certificate %s in trust store %s of type %s is invalid: %v", certFileName, namedStore, storeType, err.Error())}
				}
			}
		}
		certificates = append(certificates, certs...)
	}
	if len(certificates) < 1 {
		return nil, CertificateError{InnerError: fs.ErrNotExist, Msg: fmt.Sprintf("no x509 certificates were found in trust store %q of type %q", namedStore, storeType)}
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

// isRootCACertificate returns nil if cert is a root CA certificate
func isRootCACertificate(cert *x509.Certificate) error {
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return fmt.Errorf("certificate with subject %q is not a root CA certificate: %w", cert.Subject, err)
	}
	if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return fmt.Errorf("certificate with subject %q is not a root CA certificate: issuer (%s) and subject (%s) are not the same", cert.Subject, cert.Issuer, cert.Subject)
	}
	return nil
}
