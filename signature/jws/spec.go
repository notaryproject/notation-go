// Package jws signs and verifies artifacts with signatures in JWS format.
// The specification is currently underdiscussion and is not yet finalized.
// Reference: https://github.com/notaryproject/notaryproject/pull/93
package jws

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/notaryproject/notation-go"
)

type notaryClaim struct {
	jwt.RegisteredClaims
	Subject notation.Descriptor `json:"subject"`
}

// packPayload generates JWS payload according the signing content and options.
func packPayload(desc notation.Descriptor, opts notation.SignOptions) jwt.Claims {
	var expiresAt *jwt.NumericDate
	if !opts.Expiry.IsZero() {
		expiresAt = jwt.NewNumericDate(opts.Expiry)
	}
	return notaryClaim{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: expiresAt,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Subject: desc,
	}
}

var (
	oidExtensionKeyUsage = []int{2, 5, 29, 15}
)

// verifyCertExtKeyUsage checks cert meets the requirements defined in
// https://github.com/notaryproject/notaryproject/blob/main/signature-specification.md#certificate-requirements.
func verifyCertExtKeyUsage(cert *x509.Certificate, extKeyUsage x509.ExtKeyUsage) error {
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("keyUsage must have the bit positions for digitalSignature set")
	}
	var hasExtKeyUsage bool
	for _, ext := range cert.ExtKeyUsage {
		if ext == extKeyUsage {
			hasExtKeyUsage = true
			break
		}
	}
	if !hasExtKeyUsage {
		return fmt.Errorf("extKeyUsage must contain %d", extKeyUsage)
	}
	for _, e := range cert.Extensions {
		if e.Id.Equal(oidExtensionKeyUsage) {
			if !e.Critical {
				return errors.New("the keyUsage extension must be marked critical")
			}
			break
		}
	}
	if cert.BasicConstraintsValid && cert.IsCA {
		return errors.New("if the basicConstraints extension is present, the CA field MUST be set false")
	}
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 {
			return errors.New("RSA public key length must be 2048 bits or higher")
		}
	case *ecdsa.PublicKey:
		if key.Params().N.BitLen() < 256 {
			return errors.New("ECDSA public key length must be 256 bits or higher")
		}
	}
	return nil
}
