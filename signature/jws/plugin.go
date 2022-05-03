package jws

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/plugin"
)

var supportedAlgs = map[string]bool{
	jwt.SigningMethodPS256.Name: true,
	jwt.SigningMethodPS384.Name: true,
	jwt.SigningMethodPS512.Name: true,
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
	token := &jwt.Token{
		Header: map[string]interface{}{
			"cty": MediaTypeNotationPayload,
			"crit": []string{
				"cty",
			},
		},
		Claims: payload,
	}
	signing, err := token.SigningString()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signing payload: %w", err)
	}
	// Execute plugin.
	req := plugin.GenerateSignatureRequest{
		ContractVersion: "1",
		KeyName:         s.KeyName,
		KeyID:           s.KeyID,
		Payload:         base64.RawStdEncoding.EncodeToString([]byte(signing)),
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

	// Verify the hash of the request payload against the response signature
	// using the public key of the signing certificate.
	certs, err := parseCertChainBase64(resp.CertificateChain)
	if err != nil {
		return nil, err
	}

	signed, err := base64.RawStdEncoding.DecodeString(resp.Signature)
	if err != nil {
		return nil, err
	}
	base64Signed := base64.RawURLEncoding.EncodeToString(signed)
	err = verifyJWT(resp.SigningAlgorithm, signing, base64Signed, certs)
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
	compact := strings.Join([]string{signing, resp.Signature}, ".")
	return jwtEnvelop(ctx, opts, compact, rawCerts)
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

func verifyJWT(sigAlg string, payload, sig string, certChain []*x509.Certificate) error {
	if len(certChain) == 0 {
		return nil
	}
	signingCert := certChain[0]
	// Verify the hash of req.payload against resp.signature using the public key if the leaf certificate.
	method := jwt.GetSigningMethod(sigAlg)
	return method.Verify(payload, sig, signingCert.PublicKey)
}
