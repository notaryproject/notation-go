package jws

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/crypto/jwsutil"
	"github.com/notaryproject/notation-go/plugin"
)

var supportedAlgs = map[string]bool{
	jwt.SigningMethodES256.Name: true,
	jwt.SigningMethodES384.Name: true,
	jwt.SigningMethodES512.Name: true,
	jwt.SigningMethodES256.Name: true,
	jwt.SigningMethodES384.Name: true,
	jwt.SigningMethodES512.Name: true,
}

type PluginRunner interface {
	Run(ctx context.Context, pluginName string, cmd plugin.Command, req interface{}) (interface{}, error)
}

type PluginSigner struct {
	Runner     PluginRunner
	PluginName string
	KeyID      string
	KeyName    string
}

func (s *PluginSigner) Sign(ctx context.Context, desc notation.Descriptor, opts notation.SignOptions) ([]byte, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	// Generate payload to be signed.
	payload := packPayload(desc, opts)
	if err := payload.Valid(); err != nil {
		return nil, err
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signing payload: %w", err)
	}

	// Execute plugin.
	req := plugin.GenerateSignatureRequest{
		ContractVersion: "1",
		KeyName:         s.KeyName,
		KeyID:           s.KeyID,
		Payload:         string(jsonPayload),
	}
	out, err := s.Runner.Run(ctx, s.PluginName, plugin.CommandGenerateSignature, req)
	if err != nil {
		return nil, fmt.Errorf("sign command failed: %w", err)
	}
	resp, ok := out.(*plugin.GenerateSignatureResponse)
	if !ok {
		return nil, fmt.Errorf("invalid sign response type %T", resp)
	}

	// Check algorithm is supported.
	if !supportedAlgs[resp.SigningAlgorithm] {
		return nil, fmt.Errorf("signing algorithm %q not supported", resp.SigningAlgorithm)
	}

	// Check payload has not been modified.
	sig, err := jwsutil.ParseCompact(resp.Signature)
	if err != nil {
		return nil, err
	}
	if sig.Payload != string(jsonPayload) {
		return nil, errors.New("signing payload has been modified")
	}

	// Verify the hash of the request payload against the response signature
	// using the public key of the signing certificate.
	certs, err := parseCertChainBase64(resp.CertificateChain)
	if err != nil {
		return nil, err
	}
	err = verifyJWT(resp.SigningAlgorithm, string(jsonPayload), resp.Signature, certs)
	if err != nil {
		return nil, err
	}

	// Check the the certificate chain conforms to the spec.
	err = checkCertChain(certs)
	if err != nil {
		return nil, err
	}

	// Assemble the JWS signature envelope.
	rawCerts := make([][]byte, len(certs))
	for i, c := range certs {
		rawCerts[i] = c.Raw
	}
	return jwtEnvelop(ctx, opts, resp.Signature, rawCerts)
}

func parseCertChainBase64(certChain []string) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, len(certChain))
	for i, data := range certChain {
		der, err := base64.RawStdEncoding.DecodeString(data)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		certs[i] = cert
	}
	return certs, nil
}

func verifyJWT(sigAlg string, payload string, sig string, certChain []*x509.Certificate) error {
	if len(certChain) == 0 {
		return nil
	}
	signingCert := certChain[0]
	// Verify the hash of req.payload against resp.signature using the public key if the leaf certificate.
	method := jwt.GetSigningMethod(sigAlg)
	err := method.Verify(payload, sig, signingCert.PublicKey)
	return err
}

func checkCertChain(certChain []*x509.Certificate) error {
	if len(certChain) == 0 {
		return nil
	}
	signingCert := certChain[0]
	roots := x509.NewCertPool()
	roots.AddCert(signingCert)
	_, err := signingCert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	})
	return err
}
