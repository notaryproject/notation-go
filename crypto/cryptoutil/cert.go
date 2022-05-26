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
	return parseCertificates(data)
}

// ParseCertificates parses certificates from either PEM or DER data
// returns an empty list if no certificates are found
func parseCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	block, rest := pem.Decode(data)
	if block == nil {
		// data may be in DER format
		cert, err := x509.ParseCertificate(data)
		if err == nil {
			certs = append(certs, cert)
		}
	} else {
		// data is in PEM format
		for block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
			block, rest = pem.Decode(rest)
		}
	}

	return certs, nil
}
