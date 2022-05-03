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

// unprotectedHeader contains the header parameters that are not integrity protected.
type unprotectedHeader struct {
	TimeStampToken []byte   `json:"timestamp,omitempty"`
	CertChain      [][]byte `json:"x5c,omitempty"`
}

// MediaTypeNotationPayload describes the media type of the payload of notation signature.
const MediaTypeNotationPayload = "application/vnd.cncf.notary.v2.jws.v1"

// payload contains the subject manifest and other attributes that have to be integrity
// protected.
type payload struct {
	Notation notationClaim `json:"notary"`
	jwt.RegisteredClaims
}

// notationClaim is the top level node and private claim, encapsulating the notary v2 data.
type notationClaim struct {
	Subject notation.Descriptor `json:"subject"`
}

// packPayload generates JWS payload according the signing content and options.
func packPayload(desc notation.Descriptor, opts notation.SignOptions) *payload {
	var expiresAt *jwt.NumericDate
	if !opts.Expiry.IsZero() {
		expiresAt = jwt.NewNumericDate(opts.Expiry)
	}
	return &payload{
		Notation: notationClaim{
			Subject: desc,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: expiresAt,
		},
	}
}

func checkCertChain(certChain []*x509.Certificate) error {
	if len(certChain) == 0 {
		return nil
	}
	if err := verifyCert(certChain[0], x509.ExtKeyUsageCodeSigning); err != nil {
		return fmt.Errorf("signing certificate does not meet the minimum requirements: %w", err)
	}
	for _, c := range certChain[1:] {
		for _, ext := range c.ExtKeyUsage {
			if ext == x509.ExtKeyUsageTimeStamping {
				if err := verifyCert(c, x509.ExtKeyUsageTimeStamping); err != nil {
					return fmt.Errorf("timestamping certificate does not meet the minimum requirements: %w", err)
				}
			}
		}
	}
	return nil
}

// validateCert checks cert meets the requirements defined in
// https://github.com/notaryproject/notaryproject/blob/main/signature-specification.md#certificate-requirements.
func verifyCert(cert *x509.Certificate, extKeyUsage x509.ExtKeyUsage) error {
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
		return fmt.Errorf("extKeyUsage must contain be %d", extKeyUsage)
	}
	for _, ext := range cert.Extensions {
		switch ext.Id[3] {
		case 15:
			if !ext.Critical {
				return errors.New("the keyUsage extension must be marked critical")
			}
		}
	}
	if cert.BasicConstraintsValid && cert.IsCA {
		return errors.New("if the basicConstraints extension is present, the cA field MUST be set false")
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
