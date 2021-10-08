package cryptoutil

import (
	"crypto/x509"
	"encoding/pem"
	"os"
)

// ReadCertificateFile reads a certificate PEM file.
func ReadCertificateFile(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseCertificatePEM(data)
}

// ParseCertificatePEM parses a certificate PEM.
func ParseCertificatePEM(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	block, rest := pem.Decode(data)
	for block != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
		block, rest = pem.Decode(rest)
	}
	return certs, nil
}
