package signature

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go/internal/envelope"
	"github.com/notaryproject/notation-go/internal/plugin"
	"github.com/notaryproject/notation-go/notation"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// signingAgent is the unprotected header field used by signature.
var signingAgent = "Notation/1.0.0"

// pluginSigner signs artifacts and generates signatures.
type pluginSigner struct {
	sigProvider       provider
	envelopeMediaType string
	keyID             string
	pluginConfig      map[string]string
}

// NewSignerPlugin creates a notation.Signer that signs artifacts and generates signatures
// by delegating the one or more operations to the named plugin,
// as defined in
// https://github.com/notaryproject/notaryproject/blob/main/specs/plugin-extensibility.md#signing-interfaces.
func NewSignerPlugin(runner plugin.Runner, keyID string, pluginConfig map[string]string, envelopeMediaType string) (notation.Signer, error) {
	if runner == nil {
		return nil, errors.New("nil plugin runner")
	}
	if keyID == "" {
		return nil, errors.New("nil signing keyID")
	}
	if err := ValidateEnvelopeMediaType(envelopeMediaType); err != nil {
		return nil, err
	}
	return &pluginSigner{
		sigProvider:       newExternalProvider(runner, keyID),
		envelopeMediaType: envelopeMediaType,
		keyID:             keyID,
		pluginConfig:      pluginConfig,
	}, nil
}

// Sign signs the artifact described by its descriptor and returns the marshalled envelope.
func (s *pluginSigner) Sign(ctx context.Context, desc ocispec.Descriptor, envelopeMediaType string, opts notation.SignOptions) ([]byte, *signature.SignerInfo, error) {
	metadata, err := s.getMetadata(ctx)
	if err != nil {
		return nil, nil, err
	}
	if !metadata.SupportsContract(plugin.ContractVersion) {
		return nil, nil, fmt.Errorf(
			"contract version %q is not in the list of the plugin supported versions %v",
			plugin.ContractVersion, metadata.SupportedContractVersions,
		)
	}
	if metadata.HasCapability(plugin.CapabilitySignatureGenerator) {
		return s.generateSignature(ctx, desc, opts)
	} else if metadata.HasCapability(plugin.CapabilityEnvelopeGenerator) {
		return s.generateSignatureEnvelope(ctx, desc, opts)
	}
	return nil, nil, fmt.Errorf("plugin does not have signing capabilities")
}

func (s *pluginSigner) getMetadata(ctx context.Context) (*plugin.Metadata, error) {
	out, err := s.sigProvider.Run(ctx, new(plugin.GetMetadataRequest))
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
	out, err := s.sigProvider.Run(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("describe-key command failed: %w", err)
	}
	resp, ok := out.(*plugin.DescribeKeyResponse)
	if !ok {
		return nil, fmt.Errorf("plugin runner returned incorrect describe-key response type '%T'", out)
	}
	return resp, nil
}

func (s *pluginSigner) generateSignature(ctx context.Context, desc ocispec.Descriptor, opts notation.SignOptions) ([]byte, *signature.SignerInfo, error) {
	// for external plugin, pass keySpec and config before signing
	if extProvider, ok := s.sigProvider.(*externalProvider); ok {
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
		ks, err := plugin.ParseKeySpec(key.KeySpec)
		if err != nil {
			return nil, nil, err
		}
		extProvider.prepareSigning(config, ks)
	}

	return generateSignatureEnvelope(ctx, s.envelopeMediaType, s.sigProvider, desc, opts)
}

func generateSignatureEnvelope(ctx context.Context, mediaType string, signer signature.Signer, desc ocispec.Descriptor, opts notation.SignOptions) ([]byte, *signature.SignerInfo, error) {
	// Generate payload to be signed.
	payload := envelope.Payload{TargetArtifact: desc}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("envelope payload can't be marshaled: %w", err)
	}

	signReq := &signature.SignRequest{
		Payload: signature.Payload{
			ContentType: mediaTypePayloadV1,
			Content:     payloadBytes,
		},
		Signer:                   signer,
		SigningTime:              time.Now(),
		ExtendedSignedAttributes: nil,
		SigningScheme:            signature.SigningSchemeX509,
		SigningAgent:             signingAgent, // TODO: include external signing plugin's name and version. https://github.com/notaryproject/notation-go/issues/80
	}

	if !opts.Expiry.IsZero() {
		signReq.Expiry = opts.Expiry
	}

	// perform signing using pluginSigProvider
	sigEnv, err := signature.NewEnvelope(mediaType)
	if err != nil {
		return nil, nil, err
	}

	sig, err := sigEnv.Sign(signReq)
	if err != nil {
		return nil, nil, err
	}

	envContent, verErr := sigEnv.Verify()
	if verErr != nil {
		return nil, nil, fmt.Errorf("signature returned by generateSignature cannot be verified: %v", verErr)
	}
	if err := ValidatePayloadContentType(&envContent.Payload); err != nil {
		return nil, nil, err
	}

	// TODO: re-enable timestamping https://github.com/notaryproject/notation-go/issues/78
	return sig, &envContent.SignerInfo, nil
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

func (s *pluginSigner) generateSignatureEnvelope(ctx context.Context, desc ocispec.Descriptor, opts notation.SignOptions) ([]byte, *signature.SignerInfo, error) {
	payload := envelope.Payload{TargetArtifact: desc}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("envelope payload can't be marshaled: %w", err)
	}
	// Execute plugin sign command.
	req := &plugin.GenerateEnvelopeRequest{
		ContractVersion:       plugin.ContractVersion,
		KeyID:                 s.keyID,
		Payload:               payloadBytes,
		SignatureEnvelopeType: s.envelopeMediaType,
		PayloadType:           mediaTypePayloadV1,
		PluginConfig:          s.mergeConfig(opts.PluginConfig),
	}
	out, err := s.sigProvider.Run(ctx, req)
	if err != nil {
		return nil, nil, fmt.Errorf("generate-envelope command failed: %w", err)
	}
	resp, ok := out.(*plugin.GenerateEnvelopeResponse)
	if !ok {
		return nil, nil, fmt.Errorf("plugin runner returned incorrect generate-envelope response type '%T'", out)
	}

	// Check signatureEnvelopeType is honored.
	if resp.SignatureEnvelopeType != req.SignatureEnvelopeType {
		return nil, nil, fmt.Errorf(
			"signatureEnvelopeType in generateEnvelope response %q does not match request %q",
			resp.SignatureEnvelopeType, req.SignatureEnvelopeType,
		)
	}

	sigEnv, err := signature.ParseEnvelope(s.envelopeMediaType, resp.SignatureEnvelope)
	if err != nil {
		return nil, nil, err
	}

	envContent, err := sigEnv.Verify()
	if err != nil {
		return nil, nil, err
	}
	if err := ValidatePayloadContentType(&envContent.Payload); err != nil {
		return nil, nil, err
	}

	var signedPayload envelope.Payload
	if err = json.Unmarshal(envContent.Payload.Content, &signedPayload); err != nil {
		return nil, nil, fmt.Errorf("signed envelope payload can't be unmarshaled: %w", err)
	}

	// TODO: Verify plugin didnot add any additional top level payload attributes. https://github.com/notaryproject/notation-go/issues/80
	if !descriptorPartialEqual(desc, signedPayload.TargetArtifact) {
		return nil, nil, errors.New("descriptor subject has changed")
	}

	return resp.SignatureEnvelope, &envContent.SignerInfo, nil
}

// descriptorPartialEqual checks if the both descriptors point to the same resource
// and that newDesc hasn't replaced or overridden existing annotations.
func descriptorPartialEqual(original, newDesc ocispec.Descriptor) bool {
	if !equal(&original, &newDesc) {
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

// Equal reports whether d and t points to the same content.
func equal(d *ocispec.Descriptor, t *ocispec.Descriptor) bool {
	return d.MediaType == t.MediaType &&
		d.Digest == t.Digest &&
		d.Size == t.Size
}
