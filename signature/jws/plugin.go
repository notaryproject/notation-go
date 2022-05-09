package jws

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/spec/v1/plugin"
	"github.com/notaryproject/notation-go/spec/v1/signature"
)

var supportedAlgs = map[string]bool{
	jwt.SigningMethodPS256.Name: true,
	jwt.SigningMethodPS384.Name: true,
	jwt.SigningMethodPS512.Name: true,
	jwt.SigningMethodES256.Name: true,
	jwt.SigningMethodES384.Name: true,
	jwt.SigningMethodES512.Name: true,
}

var keySpecToAlg = map[signature.Key]string{
	signature.RSA_2048: jwt.SigningMethodPS256.Alg(),
	signature.RSA_3072: jwt.SigningMethodPS384.Alg(),
	signature.RSA_4096: jwt.SigningMethodPS512.Alg(),
	signature.EC_256:   jwt.SigningMethodES256.Alg(),
	signature.EC_384:   jwt.SigningMethodES384.Alg(),
	signature.EC_512:   jwt.SigningMethodES512.Alg(),
}

// PluginRunner is the interface implemented by plugin/manager.Manager,
// but which can be swapped by a custom third-party implementation
// if this constrains are meet:
// - Run fails if the plugin does not exist or is not valid
// - Run returns the appropriate type for each cmd
type PluginRunner interface {
	Run(ctx context.Context, pluginName string, cmd plugin.Command, req interface{}) (interface{}, error)
}

// PluginSigner signs artifacts and generates JWS signatures
// by delegating the one or both operations to the named plugin,
// as defined in
// https://github.com/notaryproject/notaryproject/blob/main/specs/plugin-extensibility.md#signing-interfaces.
type PluginSigner struct {
	Runner       PluginRunner
	PluginName   string
	KeyID        string
	KeyName      string
	PluginConfig map[string]string
}

// Sign signs the artifact described by its descriptor, and returns the signature.
func (s *PluginSigner) Sign(ctx context.Context, desc signature.Descriptor, opts notation.SignOptions) ([]byte, error) {
	out, err := s.Runner.Run(ctx, s.PluginName, plugin.CommandGetMetadata, nil)
	if err != nil {
		return nil, fmt.Errorf("metadata command failed: %w", err)
	}
	metadata := out.(*plugin.Metadata)

	if metadata.HasCapability(plugin.CapabilitySignatureGenerator) {
		return s.generateSignature(ctx, desc, opts)
	} else if metadata.HasCapability(plugin.CapabilityEnvelopeGenerator) {
		return s.generateSignatureEnvelope(ctx, desc, opts)
	}
	return nil, fmt.Errorf("plugin %q does not have signing capabilities", s.PluginName)
}

func (s *PluginSigner) describeKey(ctx context.Context) (*plugin.DescribeKeyResponse, error) {
	req := &plugin.DescribeKeyRequest{
		ContractVersion: "1",
		KeyName:         s.KeyName,
		KeyID:           s.KeyID,
		PluginConfig:    s.PluginConfig,
	}
	out, err := s.Runner.Run(ctx, s.PluginName, plugin.CommandDescribeKey, req)
	if err != nil {
		return nil, fmt.Errorf("describe-key command failed: %w", err)
	}
	return out.(*plugin.DescribeKeyResponse), nil
}

func (s *PluginSigner) generateSignature(ctx context.Context, desc signature.Descriptor, opts notation.SignOptions) ([]byte, error) {
	// Get key info.
	key, err := s.describeKey(ctx)
	if err != nil {
		return nil, err
	}

	// Check keyID is honored.
	if s.KeyID != key.KeyID {
		return nil, fmt.Errorf("keyID mismatch")
	}

	// Get algorithm associated to key.
	alg := keySpecToAlg[key.KeySpec]
	if alg == "" {
		return nil, fmt.Errorf("keySpec %q not supported: ", key.KeySpec)
	}

	// Generate payload to be signed.
	payload := packPayload(desc, opts)
	if err := payload.Valid(); err != nil {
		return nil, err
	}

	// Generate signing string.
	token := jwtToken(alg, payload)
	signing, err := token.SigningString()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signing payload: %v", err)
	}

	// Execute plugin sign command.
	req := &plugin.GenerateSignatureRequest{
		ContractVersion: "1",
		KeyName:         s.KeyName,
		KeyID:           s.KeyID,
		KeySpec:         key.KeySpec,
		Hash:            key.KeySpec.Hash(),
		Payload:         signing,
		PluginConfig:    s.PluginConfig,
	}
	out, err := s.Runner.Run(ctx, s.PluginName, plugin.CommandGenerateSignature, req)
	if err != nil {
		return nil, fmt.Errorf("generate-signature command failed: %w", err)
	}
	resp := out.(*plugin.GenerateSignatureResponse)

	// Check keyID is honored.
	if s.KeyID != resp.KeyID {
		return nil, fmt.Errorf("keyID mismatch")
	}

	// Check algorithm is supported.
	if !supportedAlgs[resp.SigningAlgorithm] {
		return nil, fmt.Errorf("signing algorithm %q not supported", resp.SigningAlgorithm)
	}

	// Check certificate chain is not empty.
	if len(resp.CertificateChain) == 0 {
		return nil, errors.New("empty certificate chain")
	}

	certs, err := parseCertChain(resp.CertificateChain)
	if err != nil {
		return nil, err
	}

	// Verify the hash of the request payload against the response signature
	// using the public key of the signing certificate.
	signed, err := base64.RawStdEncoding.DecodeString(resp.Signature)
	if err != nil {
		return nil, fmt.Errorf("signature not base64-encoded: %v", err)
	}
	signed64Url := base64.RawURLEncoding.EncodeToString(signed)
	err = verifyJWT(resp.SigningAlgorithm, signing, signed64Url, certs[0])
	if err != nil {
		return nil, fmt.Errorf("verification error: %v", err)
	}

	// Check the the certificate chain conforms to the spec.
	err = checkCertChain(certs)
	if err != nil {
		return nil, err
	}

	// Assemble the JWS signature envelope.
	rawCerts := make([]string, len(certs))
	for i, cert := range certs {
		rawCerts[i] = base64.RawStdEncoding.EncodeToString(cert.Raw)
	}
	return jwtEnvelop(ctx, opts, signing+"."+signed64Url, rawCerts)
}

func (s *PluginSigner) generateSignatureEnvelope(ctx context.Context, desc signature.Descriptor, opts notation.SignOptions) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func parseCertChain(certChain []string) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, len(certChain))
	for i, data := range certChain {
		der, err := base64.RawStdEncoding.DecodeString(data)
		if err != nil {
			return nil, fmt.Errorf("certificate not base64-encoded: %v", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		certs[i] = cert
	}
	return certs, nil
}

func verifyJWT(sigAlg string, payload string, sig string, signingCert *x509.Certificate) error {
	// Verify the hash of req.payload against resp.signature using the public key if the leaf certificate.
	method := jwt.GetSigningMethod(sigAlg)
	return method.Verify(payload, sig, signingCert.PublicKey)
}
