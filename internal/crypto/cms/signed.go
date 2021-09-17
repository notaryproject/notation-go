package cms

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"hash"
	"time"

	"github.com/notaryproject/notation-go-lib/internal/crypto/oid"
)

// ParsedSignedData is a parsed SignedData structure for golang friendly types.
type ParsedSignedData struct {
	Content      []byte
	ContentType  asn1.ObjectIdentifier
	Certificates []*x509.Certificate
	CRLs         []pkix.CertificateList
	Signers      []SignerInfo
}

// ParseSignedData parses ASN.1 DER-encoded SignedData structure to golang friendly types.
func ParseSignedData(data []byte) (*ParsedSignedData, error) {
	var contentInfo ContentInfo
	if _, err := asn1.Unmarshal(data, &contentInfo); err != nil {
		return nil, SyntaxError{Message: "invalid content info", Detail: err}
	}
	if !oid.SignedData.Equal(contentInfo.ContentType) {
		return nil, ErrExpectSignedData
	}

	var signedData SignedData
	if _, err := asn1.Unmarshal(contentInfo.Content.Bytes, &signedData); err != nil {
		return nil, SyntaxError{Message: "invalid signed data", Detail: err}
	}
	certs, err := x509.ParseCertificates(signedData.Certificates.Bytes)
	if err != nil {
		return nil, SyntaxError{Message: "invalid signed data", Detail: err}
	}

	return &ParsedSignedData{
		Content:      signedData.EncapsulatedContentInfo.Content,
		ContentType:  signedData.EncapsulatedContentInfo.ContentType,
		Certificates: certs,
		CRLs:         signedData.CRLs,
		Signers:      signedData.SignerInfos,
	}, nil
}

// Verify attempts to verify the content in the parsed signed data against the signer
// information. The `Intermediates` in the verify options will be ignored and
// re-contrusted using the certificates in the parsed signed data.
// If more than one signature is present, the successful validation of any signature
// implies that the content in the parsed signed data is valid.
// On successful verification, the list of signers that successfully verify is returned.
// If all signatures fail to verify, the last error is returned.
// References:
// - RFC 5652 5   Signed-data Content Type
// - RFC 5652 5.4 Message Digest Calculation Process
// - RFC 5652 5.6 Signature Verification Process
// WARNING: this function doesn't do any revocation checking.
func (d *ParsedSignedData) Verify(opts x509.VerifyOptions) ([]SignerInfo, error) {
	if len(d.Signers) == 0 {
		return nil, ErrSignerNotFound
	}
	if len(d.Certificates) == 0 {
		return nil, ErrCertificateNotFound
	}

	intermediates := x509.NewCertPool()
	for _, cert := range d.Certificates {
		intermediates.AddCert(cert)
	}
	opts.Intermediates = intermediates
	var verifiedSigners []SignerInfo
	var lastErr error
	for _, signer := range d.Signers {
		if err := d.verify(signer, opts); err != nil {
			lastErr = err
		} else {
			verifiedSigners = append(verifiedSigners, signer)
		}
	}
	if len(verifiedSigners) == 0 {
		return nil, lastErr
	}
	return verifiedSigners, nil
}

// verify verifies the trust in a top-down manner.
// References:
// - RFC 5652 5.4 Message Digest Calculation Process
// - RFC 5652 5.6 Signature Verification Process
func (d *ParsedSignedData) verify(signer SignerInfo, opts x509.VerifyOptions) error {
	// find signer certificate
	cert := d.getCertificate(signer.SignerIdentifier)
	if cert == nil {
		return ErrCertificateNotFound
	}

	// verify signer certificate
	if _, err := cert.Verify(opts); err != nil {
		return VerificationError{Detail: err}
	}

	// verify signature
	algorithm := getSignatureAlgorithmFromOID(
		signer.DigestAlgorithm.Algorithm,
		signer.SignatureAlgorithm.Algorithm,
	)
	if algorithm == x509.UnknownSignatureAlgorithm {
		return VerificationError{Message: "unknown signature algorithm"}
	}
	signed := d.Content
	if len(signer.SignedAttributes) > 0 {
		encoded, err := asn1.MarshalWithParams(signer.SignedAttributes, "set")
		if err != nil {
			return VerificationError{Message: "invalid signed attributes", Detail: err}
		}
		signed = encoded
	}
	if err := cert.CheckSignature(algorithm, signed, signer.Signature); err != nil {
		return VerificationError{Detail: err}
	}

	// verify attributes if present
	if len(signer.SignedAttributes) == 0 {
		return nil
	}

	var contentType asn1.ObjectIdentifier
	if err := signer.SignedAttributes.TryGet(oid.ContentType, &contentType); err != nil {
		return VerificationError{Message: "invalid content type", Detail: err}
	}
	if !d.ContentType.Equal(contentType) {
		return VerificationError{Message: "mismatch content type"}
	}

	var expectedDigest []byte
	if err := signer.SignedAttributes.TryGet(oid.MessageDigest, &expectedDigest); err != nil {
		return VerificationError{Message: "invalid message digest", Detail: err}
	}
	hash, ok := getHashFromOID(signer.DigestAlgorithm.Algorithm)
	if !ok {
		return VerificationError{Message: "unsupported digest algorithm"}
	}
	if _, err := hash.Write(d.Content); err != nil {
		return VerificationError{Message: "hash failure", Detail: err}
	}
	actualDigest := hash.Sum(nil)
	if !bytes.Equal(expectedDigest, actualDigest) {
		return VerificationError{Message: "mismatch message digest"}
	}

	// sanity check on signing time
	var signingTime time.Time
	if err := signer.SignedAttributes.TryGet(oid.SigningTime, &signingTime); err != nil {
		if err == ErrAttributeNotFound {
			return nil
		}
		return VerificationError{Message: "invalid signing time", Detail: err}
	}
	if signingTime.Before(cert.NotBefore) || signingTime.After(cert.NotAfter) {
		return VerificationError{Message: "signature signed when cert is inactive"}
	}

	return nil
}

// getCertificate finds the certificate by issuer name and issuer-specific
// serial number.
// Reference: RFC 5652 5 Signed-data Content Type
func (d *ParsedSignedData) getCertificate(ref IssuerAndSerialNumber) *x509.Certificate {
	for _, cert := range d.Certificates {
		if bytes.Equal(cert.RawIssuer, ref.Issuer.FullBytes) && cert.SerialNumber.Cmp(ref.SerialNumber) == 0 {
			return cert
		}
	}
	return nil
}

// getSignatureAlgorithmFromOID converts ASN.1 digest and signature algorithm identifiers
// to golang signature algorithms.
func getSignatureAlgorithmFromOID(digestAlg, sigAlg asn1.ObjectIdentifier) x509.SignatureAlgorithm {
	switch {
	case oid.RSA.Equal(sigAlg):
		switch {
		case oid.SHA1.Equal(digestAlg):
			return x509.SHA1WithRSA
		case oid.SHA256.Equal(digestAlg):
			return x509.SHA256WithRSA
		case oid.SHA384.Equal(digestAlg):
			return x509.SHA384WithRSA
		case oid.SHA512.Equal(digestAlg):
			return x509.SHA512WithRSA
		}
	case oid.SHA1WithRSA.Equal(sigAlg):
		return x509.SHA1WithRSA
	case oid.SHA256WithRSA.Equal(sigAlg):
		return x509.SHA256WithRSA
	case oid.SHA384WithRSA.Equal(sigAlg):
		return x509.SHA384WithRSA
	case oid.SHA512WithRSA.Equal(sigAlg):
		return x509.SHA512WithRSA
	case oid.ECDSAWithSHA1.Equal(sigAlg):
		return x509.ECDSAWithSHA1
	case oid.ECDSAWithSHA256.Equal(sigAlg):
		return x509.ECDSAWithSHA256
	case oid.ECDSAWithSHA384.Equal(sigAlg):
		return x509.ECDSAWithSHA384
	case oid.ECDSAWithSHA512.Equal(sigAlg):
		return x509.ECDSAWithSHA512
	}
	return x509.UnknownSignatureAlgorithm
}

// getHashFromOID converts ASN.1 digest algorithm identifier to golang crypto hash
// if it is available.
func getHashFromOID(digestAlg asn1.ObjectIdentifier) (hash.Hash, bool) {
	var hash crypto.Hash
	switch {
	case oid.SHA1.Equal(digestAlg):
		hash = crypto.SHA1
	case oid.SHA256.Equal(digestAlg):
		hash = crypto.SHA256
	case oid.SHA384.Equal(digestAlg):
		hash = crypto.SHA384
	case oid.SHA512.Equal(digestAlg):
		hash = crypto.SHA512
	default:
		return nil, false
	}
	return hash.New(), hash.Available()
}
