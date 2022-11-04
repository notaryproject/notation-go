package signature

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/notaryproject/notation-go/notation"
)

// NewSignerFromFiles creates a signer from key, certificate files
// TODO: Add tests for this method. https://github.com/notaryproject/notation-go/issues/80
func NewSignerFromFiles(keyPath, certPath, envelopeMediaType string) (notation.Signer, error) {
	if keyPath == "" {
		return nil, errors.New("key path not specified")
	}
	if certPath == "" {
		return nil, errors.New("certificate path not specified")
	}

	// read key / cert pair
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("%q does not contain a signer certificate chain", certPath)
	}

	// parse cert
	certs := make([]*x509.Certificate, len(cert.Certificate))
	for i, c := range cert.Certificate {
		certs[i], err = x509.ParseCertificate(c)
		if err != nil {
			return nil, err
		}
	}

	// create signer
	return NewSigner(cert.PrivateKey, certs, envelopeMediaType)
}

// NewSigner creates a signer with the recommended signing method and a signing key bundled
// with a certificate chain.
// The relation of the provided signing key and its certificate chain is not verified,
// and should be verified by the caller.
func NewSigner(key crypto.PrivateKey, certChain []*x509.Certificate, envelopeMediaType string) (notation.Signer, error) {
	builtinProvider, err := newBuiltinProvider(key, certChain)
	if err != nil {
		return nil, err
	}
	if err := ValidateEnvelopeMediaType(envelopeMediaType); err != nil {
		return nil, err
	}
	signer := &pluginSigner{
		sigProvider:       builtinProvider,
		envelopeMediaType: envelopeMediaType,
	}
	return signer, nil
}
