package signer

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/internal/envelope"
	"github.com/notaryproject/notation-go/plugin"
	"github.com/notaryproject/notation-go/plugin/proto"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
)

// pluginSigner signs artifacts and generates signatures.
// It implements notation.Signer
type pluginSigner struct {
	plugin       plugin.SignPlugin
	keyID        string
	pluginConfig map[string]string
}

// NewSignerPlugin creates a notation.Signer that signs artifacts and generates
// signatures by delegating the one or more operations to the named plugin,
// as defined in https://github.com/notaryproject/notaryproject/blob/main/specs/plugin-extensibility.md#signing-interfaces.
func NewFromPlugin(plugin plugin.Plugin, keyID string, pluginConfig map[string]string) (notation.Signer, error) {
	if plugin == nil {
		return nil, errors.New("nil plugin")
	}
	if keyID == "" {
		return nil, errors.New("keyID not specified")
	}

	return &pluginSigner{
		plugin:       plugin,
		keyID:        keyID,
		pluginConfig: pluginConfig,
	}, nil
}

// Sign signs the artifact described by its descriptor and returns the
// marshalled envelope.
func (s *pluginSigner) Sign(ctx context.Context, desc ocispec.Descriptor, opts notation.SignOptions) ([]byte, *signature.SignerInfo, error) {
	req := &proto.GetMetadataRequest{
		PluginConfig: s.mergeConfig(opts.PluginConfig),
	}
	metadata, err := s.plugin.GetMetadata(ctx, req)
	if err != nil {
		return nil, nil, err
	}
	if !metadata.SupportsContract(proto.ContractVersion) {
		return nil, nil, fmt.Errorf(
			"contract version %q is not in the list of the plugin supported versions %v",
			proto.ContractVersion, metadata.SupportedContractVersions,
		)
	}
	if metadata.HasCapability(proto.CapabilitySignatureGenerator) {
		return s.generateSignature(ctx, desc, opts)
	} else if metadata.HasCapability(proto.CapabilityEnvelopeGenerator) {
		return s.generateSignatureEnvelope(ctx, desc, opts)
	}
	return nil, nil, fmt.Errorf("plugin does not have signing capabilities")
}

func (s *pluginSigner) generateSignature(ctx context.Context, desc ocispec.Descriptor, opts notation.SignOptions) ([]byte, *signature.SignerInfo, error) {
	config := s.mergeConfig(opts.PluginConfig)
	// Get key info.
	key, err := s.describeKey(ctx, config)
	if err != nil {
		return nil, nil, err
	}

	// Check keyID is honored.
	if s.keyID != key.KeyID {
		return nil, nil, fmt.Errorf("keyID in describeKey response %q does not match request %q", key.KeyID, s.keyID)
	}
	ks, err := proto.DecodeKeySpec(key.KeySpec)
	if err != nil {
		return nil, nil, err
	}

	genericSigner := genericSigner{
		Signer: &pluginPrimitiveSigner{
			ctx:          ctx,
			plugin:       s.plugin,
			pluginConfig: config,
			keySpec:      ks,
			keyID:        s.keyID,
		},
	}

	return generateSignatureBlob(genericSigner.Signer, desc, opts)
}

func (s *pluginSigner) generateSignatureEnvelope(ctx context.Context, desc ocispec.Descriptor, opts notation.SignOptions) ([]byte, *signature.SignerInfo, error) {
	payload := envelope.Payload{TargetArtifact: envelope.SanitizeTargetArtifact(desc)}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("envelope payload can't be marshalled: %w", err)
	}
	// Execute plugin sign command.
	req := &proto.GenerateEnvelopeRequest{
		ContractVersion:       proto.ContractVersion,
		KeyID:                 s.keyID,
		Payload:               payloadBytes,
		SignatureEnvelopeType: opts.SignatureMediaType,
		PayloadType:           envelope.MediaTypePayloadV1,
		PluginConfig:          s.mergeConfig(opts.PluginConfig),
	}
	resp, err := s.plugin.GenerateEnvelope(ctx, req)
	if err != nil {
		return nil, nil, fmt.Errorf("plugin failed to sign with following error: %w", err)
	}

	// Check signatureEnvelopeType is honored.
	if resp.SignatureEnvelopeType != req.SignatureEnvelopeType {
		return nil, nil, fmt.Errorf(
			"signatureEnvelopeType in generateEnvelope response %q does not match request %q",
			resp.SignatureEnvelopeType, req.SignatureEnvelopeType,
		)
	}

	sigEnv, err := signature.ParseEnvelope(opts.SignatureMediaType, resp.SignatureEnvelope)
	if err != nil {
		return nil, nil, err
	}

	envContent, err := sigEnv.Verify()
	if err != nil {
		return nil, nil, fmt.Errorf("generated signature failed verification: %w", err)
	}
	if err := envelope.ValidatePayloadContentType(&envContent.Payload); err != nil {
		return nil, nil, err
	}

	var signedPayload envelope.Payload
	if err = json.Unmarshal(envContent.Payload.Content, &signedPayload); err != nil {
		return nil, nil, fmt.Errorf("signed envelope payload can't be unmarshalled: %w", err)
	}

	// TODO: Verify plugin did not add any additional top level payload
	// attributes. https://github.com/notaryproject/notation-go/issues/80
	if !isDescriptorSubset(desc, signedPayload.TargetArtifact) {
		return nil, nil, fmt.Errorf("during signing descriptor subject has changed from %+v to %+v", desc, signedPayload.TargetArtifact)
	}

	return resp.SignatureEnvelope, &envContent.SignerInfo, nil
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

func (s *pluginSigner) describeKey(ctx context.Context, config map[string]string) (*proto.DescribeKeyResponse, error) {
	req := &proto.DescribeKeyRequest{
		ContractVersion: proto.ContractVersion,
		KeyID:           s.keyID,
		PluginConfig:    config,
	}
	resp, err := s.plugin.DescribeKey(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("describe-key command failed: %w", err)
	}

	return resp, nil
}

// isDescriptorSubset checks if the both descriptors point to the same
// resource and that newDesc hasn't replaced or overridden existing annotations.
func isDescriptorSubset(original, newDesc ocispec.Descriptor) bool {
	if !content.Equal(original, newDesc) {
		return false
	}
	// Plugins may append additional annotations but not replace/override
	// existing.
	for k, v := range original.Annotations {
		if v2, ok := newDesc.Annotations[k]; !ok || v != v2 {
			return false
		}
	}
	return true
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

// pluginPrimitiveSigner implements signature.Signer
type pluginPrimitiveSigner struct {
	ctx          context.Context
	plugin       plugin.SignPlugin
	pluginConfig map[string]string
	keySpec      signature.KeySpec
	keyID        string
}

// Sign signs the digest by calling the underlying plugin.
func (s *pluginPrimitiveSigner) Sign(payload []byte) ([]byte, []*x509.Certificate, error) {
	// Execute plugin sign command.
	keySpec, err := proto.EncodeKeySpec(s.keySpec)
	if err != nil {
		return nil, nil, err
	}

	keySpecHash, err := proto.HashAlgorithmFromKeySpec(s.keySpec)
	if err != nil {
		return nil, nil, err
	}

	req := &proto.GenerateSignatureRequest{
		ContractVersion: proto.ContractVersion,
		KeyID:           s.keyID,
		KeySpec:         keySpec,
		Hash:            keySpecHash,
		Payload:         payload,
		PluginConfig:    s.pluginConfig,
	}

	resp, err := s.plugin.GenerateSignature(s.ctx, req)
	if err != nil {
		return nil, nil, fmt.Errorf("generate-signature command failed: %w", err)
	}

	// Check keyID is honored.
	if req.KeyID != resp.KeyID {
		return nil, nil, fmt.Errorf("keyID in generateSignature response %q does not match request %q", resp.KeyID, req.KeyID)
	}

	var certs []*x509.Certificate
	if certs, err = parseCertChain(resp.CertificateChain); err != nil {
		return nil, nil, err
	}
	return resp.Signature, certs, nil
}

// KeySpec returns the keySpec of a keyID by calling describeKey and do some
// keySpec validation.
func (s *pluginPrimitiveSigner) KeySpec() (signature.KeySpec, error) {
	return s.keySpec, nil
}
