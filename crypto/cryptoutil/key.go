package cryptoutil

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// ReadPrivateKeyFile reads a key PEM file as a signing key.
func ReadPrivateKeyFile(path string) (crypto.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKeyPEM(data)
}

// ParsePrivateKeyPEM parses a PEM as a signing key.
func ParsePrivateKeyPEM(data []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM data found")
	}
	switch block.Type {
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
}
