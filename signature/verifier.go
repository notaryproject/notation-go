package signature

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/notaryproject/notation-core-go/signer"
	x509n "github.com/notaryproject/notation-core-go/x509"
	"github.com/notaryproject/notation-go"
)

// // maxTimestampAccuracy specifies the max acceptable accuracy for timestamp.
// const maxTimestampAccuracy = time.Minute

// Verifier verifies artifacts against JWS signatures.
type Verifier struct {
	TrustedCerts []*x509.Certificate
}

// NewVerifier creates a verifier with a set of trusted verification keys.
// Callers may be interested in options in the public field of the Verifier, especially
// VerifyOptions for setting up trusted certificates.
func NewVerifier() *Verifier {
	return &Verifier{}
}

// NewVerifierFromFiles creates a verifier from certificate files
func NewVerifierFromFiles(certPaths []string) (*Verifier, error) {
	certs := make([]*x509.Certificate, len(certPaths))
	for _, path := range certPaths {
		cs, err := x509n.ReadCertificateFile(path)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cs...)
	}
	return &Verifier{TrustedCerts: certs}, nil
}

// Verify verifies the signature and returns the verified descriptor and
// metadata of the signed artifact.
func (v *Verifier) Verify(_ context.Context, sig []byte, opts notation.VerifyOptions) (notation.Descriptor, error) {
	sigEnv, err := signer.NewSignatureEnvelopeFromBytes(sig, signer.MediaTypeJWSJson)
	if err != nil {
		return notation.Descriptor{}, err
	}

	sigInfo, err := sigEnv.Verify()
	if err != nil {
		return notation.Descriptor{}, err
	}

	_, authErr := signer.VerifyAuthenticity(sigInfo, v.TrustedCerts)
	if authErr != nil {
		return notation.Descriptor{}, authErr
	}

	// TODO: validate expiry and timestamp https://github.com/notaryproject/notation-go/issues/78
	var payload notation.Payload
	if err = json.Unmarshal(sigInfo.Payload, &payload); err != nil {
		return notation.Descriptor{}, fmt.Errorf("envelope payload can't be decoded: %w", err)
	}

	return payload.TargetArtifact, nil
}
//
// // verifySigner verifies the signing identity and returns the verification key.
// func (v *Verifier) verifySigner(sig *notation.JWSEnvelope) (crypto.PublicKey, error) {
// 	if len(sig.Header.CertChain) == 0 {
// 		return nil, errors.New("signer certificates not found")
// 	}
// 	return v.verifySignerFromCertChain(sig.Header.CertChain, sig.Header.TimeStampToken, sig.Signature)
// }
//
// // verifySignerFromCertChain verifies the signing identity from the provided certificate
// // chain and returns the verification key. The first certificate of the certificate chain
// // contains the key, which used to sign the artifact.
// // Reference: RFC 7515 4.1.6 "x5c" (X.509 Certificate Chain) Header Parameter.
// func (v *Verifier) verifySignerFromCertChain(certChain [][]byte, timeStampToken []byte, encodedSig string) (crypto.PublicKey, error) {
// 	// prepare for certificate verification
// 	certs := make([]*x509.Certificate, 0, len(certChain))
// 	for _, certBytes := range certChain {
// 		cert, err := x509.ParseCertificate(certBytes)
// 		if err != nil {
// 			return nil, err
// 		}
// 		certs = append(certs, cert)
// 	}
// 	intermediates := x509.NewCertPool()
// 	for _, cert := range certs[1:] {
// 		intermediates.AddCert(cert)
// 	}
// 	verifyOpts := v.VerifyOptions
// 	verifyOpts.Intermediates = intermediates
// 	if len(verifyOpts.KeyUsages) == 0 {
// 		verifyOpts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
// 	}
//
// 	// verify the signing certificate
// 	checkTimestamp := v.EnforceExpiryValidation
// 	cert := certs[0]
// 	if _, err := cert.Verify(verifyOpts); err != nil {
// 		if certErr, ok := err.(x509.CertificateInvalidError); !ok || certErr.Reason != x509.Expired {
// 			return nil, err
// 		}
//
// 		// verification failed due to expired certificate
// 		checkTimestamp = true
// 	}
// 	if checkTimestamp {
// 		stampedTime, err := v.verifyTimestamp(timeStampToken, encodedSig)
// 		if err != nil {
// 			return nil, err
// 		}
// 		verifyOpts.CurrentTime = stampedTime
// 		if _, err := cert.Verify(verifyOpts); err != nil {
// 			return nil, err
// 		}
// 	}
// 	return cert.PublicKey, nil
// }
//
// // verifyTimestamp verifies the timestamp token and returns stamped time.
// func (v *Verifier) verifyTimestamp(tokenBytes []byte, encodedSig string) (time.Time, error) {
// 	sig, err := base64.RawURLEncoding.DecodeString(encodedSig)
// 	if err != nil {
// 		return time.Time{}, err
// 	}
// 	return verifyTimestamp(sig, tokenBytes, v.TSARoots)
// }
//
// // verifyTimestamp verifies the timestamp token and returns stamped time.
// func verifyTimestamp(contentBytes, tokenBytes []byte, roots *x509.CertPool) (time.Time, error) {
// 	token, err := timestamp.ParseSignedToken(tokenBytes)
// 	if err != nil {
// 		return time.Time{}, err
// 	}
// 	opts := x509.VerifyOptions{
// 		Roots: roots,
// 	}
// 	if _, err := token.Verify(opts); err != nil {
// 		return time.Time{}, err
// 	}
// 	info, err := token.Info()
// 	if err != nil {
// 		return time.Time{}, err
// 	}
// 	if err := info.Verify(contentBytes); err != nil {
// 		return time.Time{}, err
// 	}
// 	stampedTime, accuracy := info.Timestamp()
// 	if accuracy > maxTimestampAccuracy {
// 		return time.Time{}, fmt.Errorf("max timestamp accuracy exceeded: %v", accuracy)
// 	}
// 	return stampedTime, nil
// }
