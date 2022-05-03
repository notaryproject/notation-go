package jws

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
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
	out, err := s.Runner.Run(ctx, s.PluginName, plugin.CommandGetMetadata, nil)
	if err != nil {
		return nil, fmt.Errorf("metadata command failed: %w", err)
	}
	metadata := out.(*plugin.Metadata)

	// Generate payload to be signed.
	payload := packPayload(desc, opts)
	if err := payload.Valid(); err != nil {
		return nil, err
	}

	if metadata.HasCapability(plugin.CapabilitySignatureGenerator) {
		return s.generateSignature(ctx, opts, payload)
	} else if metadata.HasCapability(plugin.CapabilityEnvelopeGenerator) {

	}
	return nil, fmt.Errorf("plugin %q does not have signing capabilities", s.PluginName)
}

func (s *PluginSigner) describeKey(ctx context.Context) (*plugin.DescribeKeyResponse, error) {
	req := plugin.DescribeKeyRequest{
		ContractVersion: "1",
		KeyName:         s.KeyName,
		KeyID:           s.KeyID,
	}
	out, err := s.Runner.Run(ctx, s.PluginName, plugin.CommandDescribeKey, req)
	if err != nil {
		return nil, fmt.Errorf("describe-key command failed: %w", err)
	}
	return out.(*plugin.DescribeKeyResponse), nil
}

func (s *PluginSigner) generateSignature(ctx context.Context, opts notation.SignOptions, payload *payload) ([]byte, error) {
	// Get key info.
	key, err := s.describeKey(ctx)
	if err != nil {
		return nil, err
	}
	// Generate signing string.
	token := &jwt.Token{
		Header: map[string]interface{}{
			"alg":  key.Algorithm,
			"cty":  MediaTypeSignatureEnvelope,
			"crit": []string{"cty"},
		},
		Claims: payload,
	}
	signing, err := token.SigningString()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signing payload: %w", err)
	}

	// Execute plugin sign command.
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
	resp := out.(*plugin.GenerateSignatureResponse)

	// Check algorithm is supported.
	if !supportedAlgs[resp.SigningAlgorithm] {
		return nil, fmt.Errorf("signing algorithm %q not supported", resp.SigningAlgorithm)
	}

	certs, err := parseCertChain(resp.CertificateChain)
	if err != nil {
		return nil, err
	}

	// Verify the hash of the request payload against the response signature
	// using the public key of the signing certificate.
	signed, err := base64.RawStdEncoding.DecodeString(resp.Signature)
	if err != nil {
		return nil, err
	}
	err = verifyJWT(resp.SigningAlgorithm, signing, signed, certs)
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

func (s *PluginSigner) generateSignatureEnvelope(ctx context.Context, opts notation.SignOptions, payload *payload) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func parseCertChain(certChain []string) ([]*x509.Certificate, error) {
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

func verifyJWT(sigAlg string, payload string, sig []byte, certChain []*x509.Certificate) error {
	if len(certChain) == 0 {
		return nil
	}
	signingCert := certChain[0]
	// Verify the hash of req.payload against resp.signature using the public key if the leaf certificate.
	method := jwt.GetSigningMethod(sigAlg)
	encSig := base64.RawURLEncoding.EncodeToString(sig)
	return method.Verify(payload, encSig, signingCert.PublicKey)
}
