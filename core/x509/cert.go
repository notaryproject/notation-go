package x509

import (
	"crypto/x509"

	corex509 "github.com/notaryproject/notation-core-go/x509"
)

// ReadCertificateFile reads a certificate file (support PEM and DER formats).
func ReadCertificateFile(path string) ([]*x509.Certificate, error) {
	return corex509.ReadCertificateFile(path)
}
