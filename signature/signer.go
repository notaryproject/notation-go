package signature

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/notaryproject/notation-go"
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

// called from plugin.go
// func jwsEnvelope(ctx context.Context, opts notation.SignOptions, compact string, certChain [][]byte) ([]byte, error) {
// 	parts := strings.Split(compact, ".")
// 	if len(parts) != 3 {
// 		return nil, errors.New("invalid compact serialization")
// 	}
// 	envelope := notation.JWSEnvelope{
// 		Protected: parts[0],
// 		Payload:   parts[1],
// 		Signature: parts[2],
// 		Header: notation.JWSUnprotectedHeader{
// 			CertChain: certChain,
// 		},
// 	}
//
// 	// timestamp JWT
// 	if opts.TSA != nil {
// 		token, err := timestampSignature(ctx, envelope.Signature, opts.TSA, opts.TSAVerifyOptions)
// 		if err != nil {
// 			return nil, fmt.Errorf("timestamp failed: %w", err)
// 		}
// 		envelope.Header.TimeStampToken = token
// 	}
//
// 	// encode in flatten JWS JSON serialization
// 	return json.Marshal(envelope)
// }

// local
// timestampSignature sends a request to the TSA for timestamping the signature.
// func timestampSignature(ctx context.Context, sig string, tsa timestamp.Timestamper, opts x509.VerifyOptions) ([]byte, error) {
// 	// timestamp the signature
// 	decodedSig, err := base64.RawURLEncoding.DecodeString(sig)
// 	if err != nil {
// 		return nil, err
// 	}
// 	req, err := timestamp.NewRequestFromBytes(decodedSig)
// 	if err != nil {
// 		return nil, err
// 	}
// 	resp, err := tsa.Timestamp(ctx, req)
// 	if err != nil {
// 		return nil, err
// 	}
// 	if status := resp.Status; status.Status != pki.StatusGranted {
// 		return nil, fmt.Errorf("tsa: %d: %v", status.Status, status.StatusString)
// 	}
// 	tokenBytes := resp.TokenBytes()
//
// 	// verify the timestamp signature
// 	if _, err := verifyTimestamp(decodedSig, tokenBytes, opts.Roots); err != nil {
// 		return nil, err
// 	}
//
// 	return tokenBytes, nil
// }
