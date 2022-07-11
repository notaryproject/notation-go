package signature

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/notaryproject/notation-core-go/signer"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/plugin"
)

// pluginSigner signs artifacts and generates signatures.
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

	// Generate payload to be signed.
	payload := notation.Payload{TargetArtifact: desc}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("envelope payload can't be marshaled: %w", err)
	}

	// Create plugin signature provider
	psp := pluginSigProvider{
		runner:  s.runner,
		ctx:     ctx,
		keyID:   s.keyID,
		keySpec: key.KeySpec,
	}
	signReq := signer.SignRequest{
		Payload:             payloadBytes,
		PayloadContentType:  signer.PayloadContentTypeV1,
		SignatureProvider:   psp,
		SigningTime:         time.Now(),
		ExtendedSignedAttrs: nil,
		SigningAgent:        "Notation/1.0.0",  // TODO: include external signing plugin's name and version. https://github.com/notaryproject/notation-go/issues/80
	}
	if !opts.Expiry.IsZero() {
		signReq.Expiry = opts.Expiry
	}

	// perform signing using pluginSigProvider
	sigEnv, err := signer.NewSignatureEnvelope(signer.MediaTypeJWSJson)
	if err != nil {
		return nil, err
	}

	sig, err := sigEnv.Sign(signReq)
	if err != nil {
		return nil, err
	}

	_, verErr := sigEnv.Verify()
	if verErr != nil {
		return nil, fmt.Errorf("signature returned by generateSignature cannot be verified: %v", err)
	}

	// TODO: re-enable timestamping https://github.com/notaryproject/notation-go/issues/78
	return sig, nil
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
	payload := notation.Payload{TargetArtifact: desc}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("envelope payload can't be marshaled: %w", err)
	}
	// Execute plugin sign command.
	req := &plugin.GenerateEnvelopeRequest{
		ContractVersion:       plugin.ContractVersion,
		KeyID:                 s.keyID,
		Payload:               payloadBytes,
		SignatureEnvelopeType: string(signer.MediaTypeJWSJson),
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

	sigEnv, err := signer.NewSignatureEnvelopeFromBytes(resp.SignatureEnvelope, signer.MediaTypeJWSJson)
	if err != nil {
		return nil, err
	}

	sigInfo, err := sigEnv.Verify()
	if err != nil {
		return nil, err
	}

	var signedPayload notation.Payload
	if err = json.Unmarshal(sigInfo.Payload, &signedPayload); err != nil {
		return nil, fmt.Errorf("signed envelope payload can't be unmarshaled: %w", err)
	}

	// TODO: Verify plugin didnot add any additional top level payload attributes. https://github.com/notaryproject/notation-go/issues/80
	if !descriptorPartialEqual(desc, signedPayload.TargetArtifact) {
		return nil, errors.New("descriptor subject has changed")
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

type pluginSigProvider struct {
	runner  plugin.Runner
	ctx     context.Context
	keyID   string
	keySpec signer.KeySpec
	config  map[string]string
}

func (psp pluginSigProvider) Sign(bytes []byte) ([]byte, []*x509.Certificate, error) {
	// Execute plugin sign command.
	req := &plugin.GenerateSignatureRequest{
		ContractVersion: plugin.ContractVersion,
		KeyID:           psp.keyID,
		KeySpec:         psp.keySpec,
		Hash:            psp.keySpec.SignatureAlgorithm().Hash().String(),
		Payload:         bytes,
		PluginConfig:    psp.config,
	}

	out, err := psp.runner.Run(psp.ctx, req)
	if err != nil {
		return nil, nil, fmt.Errorf("generate-signature command failed: %w", err)
	}

	resp, ok := out.(*plugin.GenerateSignatureResponse)
	if !ok {
		return nil, nil, fmt.Errorf("plugin runner returned incorrect generate-signature response type '%T'", out)
	}

	// Check keyID is honored.
	if req.KeyID != resp.KeyID {
		return nil, nil, fmt.Errorf("keyID in generateSignature response %q does not match request %q", resp.KeyID, req.KeyID)
	}

	certs, err := parseCertChain(resp.CertificateChain)
	if err != nil {
		return nil, nil, err
	}

	return resp.Signature, certs, nil
}

func (psp pluginSigProvider) KeySpec() (signer.KeySpec, error) {
	return psp.keySpec, nil
}
