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
	"github.com/notaryproject/notation-go/plugin"
)

// pluginSigner signs artifacts and generates JWS signatures.
type pluginSigner struct {
	runner       plugin.Runner
	keyID        string
	pluginConfig map[string]string
}

// NewSignerPlugin creates a notation.Signer that signs artifacts and generates JWS signatures
// by delegating the one or more operations to the named plugin,
// as defined in
// https://github.com/notaryproject/notaryproject/blob/main/specs/plugin-extensibility.md#signing-interfaces.
func NewSignerPlugin(runner plugin.Runner, keyID string, pluginConfig map[string]string) (notation.Signer, error) {
	if runner == nil {
		return nil, errors.New("nil plugin runner")
	}
	if keyID == "" {
		return nil, errors.New("nil signing keyID")
	}
	return &pluginSigner{runner, keyID, pluginConfig}, nil
}

// Sign signs the artifact described by its descriptor, and returns the signature.
func (s *pluginSigner) Sign(ctx context.Context, desc notation.Descriptor, opts notation.SignOptions) ([]byte, error) {
	metadata, err := s.getMetadata(ctx)
	if err != nil {
		return nil, err
	}
	if !metadata.SupportsContract(plugin.ContractVersion) {
		return nil, fmt.Errorf(
			"contract version %q is not in the list of the plugin supported versions %v",
			plugin.ContractVersion, metadata.SupportedContractVersions,
		)
	}
	if metadata.HasCapability(plugin.CapabilitySignatureGenerator) {
		return s.generateSignature(ctx, desc, opts)
	} else if metadata.HasCapability(plugin.CapabilityEnvelopeGenerator) {
		return s.generateSignatureEnvelope(ctx, desc, opts)
	}
	return nil, fmt.Errorf("plugin does not have signing capabilities")
}

func (s *pluginSigner) getMetadata(ctx context.Context) (*plugin.Metadata, error) {
	out, err := s.runner.Run(ctx, new(plugin.GetMetadataRequest))
	if err != nil {
		return nil, fmt.Errorf("metadata command failed: %w", err)
	}
	metadata, ok := out.(*plugin.Metadata)
	if !ok {
		return nil, fmt.Errorf("plugin runner returned incorrect get-plugin-metadata response type '%T'", out)
	}
	if err := metadata.Validate(); err != nil {
		return nil, fmt.Errorf("invalid plugin metadata: %w", err)
	}
	return metadata, nil
}

func (s *pluginSigner) describeKey(ctx context.Context, config map[string]string) (*plugin.DescribeKeyResponse, error) {
	req := &plugin.DescribeKeyRequest{
		ContractVersion: plugin.ContractVersion,
		KeyID:           s.keyID,
		PluginConfig:    config,
	}
	out, err := s.runner.Run(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("describe-key command failed: %w", err)
	}
	resp, ok := out.(*plugin.DescribeKeyResponse)
	if !ok {
		return nil, fmt.Errorf("plugin runner returned incorrect describe-key response type '%T'", out)
	}
	return resp, nil
}

func (s *pluginSigner) generateSignature(ctx context.Context, desc notation.Descriptor, opts notation.SignOptions) ([]byte, error) {
	config := s.mergeConfig(opts.PluginConfig)
	// Get key info.
	key, err := s.describeKey(ctx, config)
	if err != nil {
		return nil, err
	}

	// Check keyID is honored.
	if s.keyID != key.KeyID {
		return nil, fmt.Errorf("keyID in describeKey response %q does not match request %q", key.KeyID, s.keyID)
	}

	// Get algorithm associated to key.
	alg := key.KeySpec.SignatureAlgorithm()
	if alg == "" {
		return nil, fmt.Errorf("keySpec %q for key %q is not supported", key.KeySpec, key.KeyID)
	}

	// Generate payload to be signed.
	payload := packPayload(desc, opts)
	if err := payload.Valid(); err != nil {
		return nil, err
	}

	// Generate signing string.
	token := jwtToken(alg.JWS(), payload)
	payloadToSign, err := token.SigningString()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signing payload: %v", err)
	}

	// Execute plugin sign command.
	req := &plugin.GenerateSignatureRequest{
		ContractVersion: plugin.ContractVersion,
		KeyID:           s.keyID,
		KeySpec:         key.KeySpec,
		Hash:            alg.Hash(),
		Payload:         []byte(payloadToSign),
		PluginConfig:    config,
	}
	out, err := s.runner.Run(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("generate-signature command failed: %w", err)
	}
	resp, ok := out.(*plugin.GenerateSignatureResponse)
	if !ok {
		return nil, fmt.Errorf("plugin runner returned incorrect generate-signature response type '%T'", out)
	}

	// Check keyID is honored.
	if s.keyID != resp.KeyID {
		return nil, fmt.Errorf("keyID in generateSignature response %q does not match request %q", resp.KeyID, s.keyID)
	}

	// Check algorithm is supported.
	jwsAlg := resp.SigningAlgorithm.JWS()
	if jwsAlg == "" {
		return nil, fmt.Errorf("signing algorithm %q in generateSignature response is not supported", resp.SigningAlgorithm)
	}

	// Check certificate chain is not empty.
	if len(resp.CertificateChain) == 0 {
		return nil, errors.New("generateSignature response has empty certificate chain")
	}

	certs, err := parseCertChain(resp.CertificateChain)
	if err != nil {
		return nil, err
	}

	// Verify the hash of the request payload against the response signature
	// using the public key of the signing certificate.
	// At this point, resp.Signature is not base64-encoded,
	// but verifyJWT expects a base64URL encoded string.
	signed64Url := base64.RawURLEncoding.EncodeToString(resp.Signature)
	err = verifyJWT(jwsAlg, payloadToSign, signed64Url, certs[0])
	if err != nil {
		return nil, fmt.Errorf("signature returned by generateSignature cannot be verified: %v", err)
	}

	// Check the the certificate chain conforms to the spec.
	if err := verifyCertExtKeyUsage(certs[0], x509.ExtKeyUsageCodeSigning); err != nil {
		return nil, fmt.Errorf("signing certificate in generateSignature response.CertificateChain does not meet the minimum requirements: %w", err)
	}

	// Assemble the JWS signature envelope.
	return jwsEnvelope(ctx, opts, payloadToSign+"."+signed64Url, resp.CertificateChain)
}

func (s *pluginSigner) mergeConfig(config map[string]string) map[string]string {
	c := make(map[string]string, len(s.pluginConfig)+len(config))
	// First clone s.PluginConfig.
	for k, v := range s.pluginConfig {
		c[k] = v
	}
	// Then set or override entries from config.
	for k, v := range config {
		c[k] = v
	}
	return c
}

func (s *pluginSigner) generateSignatureEnvelope(ctx context.Context, desc notation.Descriptor, opts notation.SignOptions) ([]byte, error) {
	rawDesc, err := json.Marshal(desc)
	if err != nil {
		return nil, err
	}
	// Execute plugin sign command.
	req := &plugin.GenerateEnvelopeRequest{
		ContractVersion:       plugin.ContractVersion,
		KeyID:                 s.keyID,
		Payload:               rawDesc,
		SignatureEnvelopeType: notation.MediaTypeJWSEnvelope,
		PayloadType:           notation.MediaTypePayload,
		PluginConfig:          s.mergeConfig(opts.PluginConfig),
	}
	out, err := s.runner.Run(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("generate-envelope command failed: %w", err)
	}
	resp, ok := out.(*plugin.GenerateEnvelopeResponse)
	if !ok {
		return nil, fmt.Errorf("plugin runner returned incorrect generate-envelope response type '%T'", out)
	}

	// Check signatureEnvelopeType is honored.
	if resp.SignatureEnvelopeType != req.SignatureEnvelopeType {
		return nil, fmt.Errorf(
			"signatureEnvelopeType in generateEnvelope response %q does not match request %q",
			resp.SignatureEnvelopeType, req.SignatureEnvelopeType,
		)
	}

	// Check signatureEnvelope contains a valid JWSEnvelope.
	var envelope notation.JWSEnvelope
	if err = json.Unmarshal(resp.SignatureEnvelope, &envelope); err != nil ||
		len(envelope.Payload) == 0 ||
		len(envelope.Protected) == 0 ||
		len(envelope.Signature) == 0 ||
		len(envelope.Header.CertChain) == 0 {

		return nil, errors.New("envelope content does not match envelope format")
	}

	// Check algorithm is supported.
	var protected notation.JWSProtectedHeader
	if err = decodeBase64URLJSON(envelope.Protected, &protected); err != nil {
		return nil, fmt.Errorf("envelope protected header can't be decoded: %w", err)
	}
	if notation.NewSignatureAlgorithmJWS(protected.Algorithm) == "" {
		return nil, fmt.Errorf("signing algorithm %q not supported", protected.Algorithm)
	}

	// Check descriptor subject is honored.
	var payload notation.JWSPayload
	err = decodeBase64URLJSON(envelope.Payload, &payload)
	if err != nil {
		return nil, fmt.Errorf("envelope payload can't be decoded: %w", err)
	}
	if !descriptorPartialEqual(desc, payload.Subject) {
		return nil, errors.New("descriptor subject has changed")
	}

	// Check signatureEnvelope can be verified against signing certificate.
	certs, err := parseCertChain(envelope.Header.CertChain)
	if err != nil {
		return nil, err
	}
	err = verifyJWT(protected.Algorithm, envelope.Protected+"."+envelope.Payload, envelope.Signature, certs[0])
	if err != nil {
		return nil, err
	}

	// Check the the certificate chain conforms to the spec.
	if err := verifyCertExtKeyUsage(certs[0], x509.ExtKeyUsageCodeSigning); err != nil {
		return nil, fmt.Errorf("signing certificate does not meet the minimum requirements: %w", err)
	}
	return resp.SignatureEnvelope, nil
}

// descriptorPartialEqual checks if the both descriptors point to the same resource
// and that newDesc hasn't replaced or overridden existing annotations.
func descriptorPartialEqual(original, newDesc notation.Descriptor) bool {
	if !original.Equal(newDesc) {
		return false
	}
	// Plugins may append additional annotations but not replace/override existing.
	for k, v := range original.Annotations {
		if v2, ok := newDesc.Annotations[k]; !ok || v != v2 {
			return false
		}
	}
	return true
}

func decodeBase64URLJSON(str string, v interface{}) error {
	dec, err := base64.RawURLEncoding.DecodeString(str)
	if err != nil {
		return err
	}
	return json.Unmarshal(dec, v)
}

func parseCertChain(certChain [][]byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, len(certChain))
	for i, cert := range certChain {
		cert, err := x509.ParseCertificate(cert)
		if err != nil {
			return nil, err
		}
		certs[i] = cert
	}
	return certs, nil
}

func verifyJWT(sigAlg string, payload string, sig string, signingCert *x509.Certificate) error {
	// Verify the hash of req.payload against resp.signature using the public key in the leaf certificate.
	method := jwt.GetSigningMethod(sigAlg)
	return method.Verify(payload, sig, signingCert.PublicKey)
}
