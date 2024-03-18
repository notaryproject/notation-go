// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package signer

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"oras.land/oras-go/v2/content"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/internal/envelope"
	"github.com/notaryproject/notation-go/log"
	"github.com/notaryproject/notation-go/plugin/proto"
	"github.com/notaryproject/notation-plugin-framework-go/plugin"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// PluginSigner signs artifacts and generates signatures.
// It implements notation.Signer
type PluginSigner struct {
	plugin              plugin.SignPlugin
	keyID               string
	pluginConfig        map[string]string
	manifestAnnotations map[string]string
}

var algorithms = map[crypto.Hash]digest.Algorithm{
	crypto.SHA256: digest.SHA256,
	crypto.SHA384: digest.SHA384,
	crypto.SHA512: digest.SHA512,
}

// NewFromPlugin creates a notation.Signer that signs artifacts and generates
// signatures by delegating the one or more operations to the named plugin,
// as defined in https://github.com/notaryproject/notaryproject/blob/main/specs/plugin-extensibility.md#signing-interfaces.
// Deprecated: NewFromPlugin function exists for historical compatibility and should not be used.
// To create PluginSigner, use NewPluginSigner() function.
func NewFromPlugin(plugin plugin.SignPlugin, keyID string, pluginConfig map[string]string) (notation.Signer, error) {
	return NewPluginSigner(plugin, keyID, pluginConfig)
}

// NewPluginSigner creates a notation.Signer that signs artifacts and generates
// signatures by delegating the one or more operations to the named plugin,
// as defined in https://github.com/notaryproject/notaryproject/blob/main/specs/plugin-extensibility.md#signing-interfaces.
func NewPluginSigner(plugin plugin.SignPlugin, keyID string, pluginConfig map[string]string) (*PluginSigner, error) {
	if plugin == nil {
		return nil, errors.New("nil plugin")
	}
	if keyID == "" {
		return nil, errors.New("keyID not specified")
	}

	return &PluginSigner{
		plugin:       plugin,
		keyID:        keyID,
		pluginConfig: pluginConfig,
	}, nil
}

// PluginAnnotations returns signature manifest annotations returned from plugin
func (s *PluginSigner) PluginAnnotations() map[string]string {
	return s.manifestAnnotations
}

// Sign signs the artifact described by its descriptor and returns the
// marshalled envelope.
func (s *PluginSigner) Sign(ctx context.Context, desc ocispec.Descriptor, opts notation.SignerSignOptions) ([]byte, *signature.SignerInfo, error) {
	logger := log.GetLogger(ctx)
	mergedConfig := s.mergeConfig(opts.PluginConfig)

	logger.Debug("Invoking plugin's get-plugin-metadata command")
	metadata, err := s.plugin.GetMetadata(ctx, &plugin.GetMetadataRequest{PluginConfig: mergedConfig})
	if err != nil {
		return nil, nil, err
	}

	logger.Debugf("Using plugin %v with capabilities %v to sign oci artifact %v in signature media type %v", metadata.Name, metadata.Capabilities, desc.Digest, opts.SignatureMediaType)
	if metadata.HasCapability(plugin.CapabilitySignatureGenerator) {
		ks, err := s.getKeySpec(ctx, mergedConfig)
		if err != nil {
			return nil, nil, err
		}
		return s.generateSignature(ctx, desc, opts, ks, metadata, mergedConfig)
	} else if metadata.HasCapability(plugin.CapabilityEnvelopeGenerator) {
		return s.generateSignatureEnvelope(ctx, desc, opts)
	}
	return nil, nil, fmt.Errorf("plugin does not have signing capabilities")
}

// SignBlob signs the arbitrary data and returns the marshalled envelope.
func (s *PluginSigner) SignBlob(ctx context.Context, descGenFunc notation.BlobDescriptorGenerator, opts notation.SignerSignOptions) ([]byte, *signature.SignerInfo, error) {
	logger := log.GetLogger(ctx)
	mergedConfig := s.mergeConfig(opts.PluginConfig)

	logger.Debug("Invoking plugin's get-plugin-metadata command")
	metadata, err := s.plugin.GetMetadata(ctx, &plugin.GetMetadataRequest{PluginConfig: mergedConfig})
	if err != nil {
		return nil, nil, err
	}

	logger.Debug("Invoking plugin's describe-key command")
	ks, err := s.getKeySpec(ctx, mergedConfig)
	if err != nil {
		return nil, nil, err
	}

	// get descriptor to sign
	desc, err := getDescriptor(ks, descGenFunc)
	if err != nil {
		return nil, nil, err
	}

	logger.Debugf("Using plugin %v with capabilities %v to sign blob using descriptor %+v", metadata.Name, metadata.Capabilities, desc)
	if metadata.HasCapability(plugin.CapabilitySignatureGenerator) {
		return s.generateSignature(ctx, desc, opts, ks, metadata, mergedConfig)
	} else if metadata.HasCapability(plugin.CapabilityEnvelopeGenerator) {
		return s.generateSignatureEnvelope(ctx, desc, opts)
	}
	return nil, nil, fmt.Errorf("plugin does not have signing capabilities")
}

func (s *PluginSigner) getKeySpec(ctx context.Context, config map[string]string) (signature.KeySpec, error) {
	logger := log.GetLogger(ctx)
	logger.Debug("Invoking plugin's describe-key command")
	descKeyResp, err := s.describeKey(ctx, config)
	if err != nil {
		return signature.KeySpec{}, err
	}

	if s.keyID != descKeyResp.KeyID {
		return signature.KeySpec{}, fmt.Errorf("keyID in describeKey response %q does not match request %q", descKeyResp.KeyID, s.keyID)
	}

	return proto.DecodeKeySpec(descKeyResp.KeySpec)
}

func (s *PluginSigner) generateSignature(ctx context.Context, desc ocispec.Descriptor, opts notation.SignerSignOptions, ks signature.KeySpec, metadata *plugin.GetMetadataResponse, pluginConfig map[string]string) ([]byte, *signature.SignerInfo, error) {
	logger := log.GetLogger(ctx)
	logger.Debug("Generating signature by plugin")
	genericSigner := GenericSigner{
		signer: &pluginPrimitiveSigner{
			ctx:          ctx,
			plugin:       s.plugin,
			keyID:        s.keyID,
			pluginConfig: pluginConfig,
			keySpec:      ks,
		},
	}

	opts.SigningAgent = fmt.Sprintf("%s %s/%s", signingAgent, metadata.Name, metadata.Version)
	return genericSigner.Sign(ctx, desc, opts)
}

func (s *PluginSigner) generateSignatureEnvelope(ctx context.Context, desc ocispec.Descriptor, opts notation.SignerSignOptions) ([]byte, *signature.SignerInfo, error) {
	logger := log.GetLogger(ctx)
	logger.Debug("Generating signature envelope by plugin")
	payload := envelope.Payload{TargetArtifact: envelope.SanitizeTargetArtifact(desc)}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("envelope payload can't be marshalled: %w", err)
	}
	// Execute plugin sign command.
	req := &plugin.GenerateEnvelopeRequest{
		KeyID:                   s.keyID,
		Payload:                 payloadBytes,
		SignatureEnvelopeType:   opts.SignatureMediaType,
		PayloadType:             envelope.MediaTypePayloadV1,
		ExpiryDurationInSeconds: uint64(opts.ExpiryDuration / time.Second),
		PluginConfig:            s.mergeConfig(opts.PluginConfig),
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

	logger.Debug("Verifying signature envelope generated by the plugin")
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

	content := envContent.Payload.Content
	var signedPayload envelope.Payload
	if err = json.Unmarshal(content, &signedPayload); err != nil {
		return nil, nil, fmt.Errorf("signed envelope payload can't be unmarshalled: %w", err)
	}

	if !isPayloadDescriptorValid(desc, signedPayload.TargetArtifact) {
		return nil, nil, fmt.Errorf("during signing descriptor subject has changed from %+v to %+v", desc, signedPayload.TargetArtifact)
	}

	if unknownAttributes := areUnknownAttributesAdded(content); len(unknownAttributes) != 0 {
		return nil, nil, fmt.Errorf("during signing, following unknown attributes were added to subject descriptor: %+q", unknownAttributes)
	}

	s.manifestAnnotations = resp.Annotations
	return resp.SignatureEnvelope, &envContent.SignerInfo, nil
}

func (s *PluginSigner) mergeConfig(config map[string]string) map[string]string {
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

func (s *PluginSigner) describeKey(ctx context.Context, config map[string]string) (*plugin.DescribeKeyResponse, error) {
	req := &plugin.DescribeKeyRequest{
		KeyID:        s.keyID,
		PluginConfig: config,
	}
	resp, err := s.plugin.DescribeKey(ctx, req)
	if err != nil {
		return nil, err
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

func isPayloadDescriptorValid(originalDesc, newDesc ocispec.Descriptor) bool {
	return content.Equal(originalDesc, newDesc) &&
		isDescriptorSubset(originalDesc, newDesc)
}

func areUnknownAttributesAdded(content []byte) []string {
	var targetArtifactMap map[string]interface{}
	// Ignoring error because we already successfully unmarshalled before this
	// point
	_ = json.Unmarshal(content, &targetArtifactMap)
	descriptor := targetArtifactMap["targetArtifact"].(map[string]interface{})

	// Explicitly remove expected keys to check if any are left over
	delete(descriptor, "mediaType")
	delete(descriptor, "digest")
	delete(descriptor, "size")
	delete(descriptor, "urls")
	delete(descriptor, "annotations")
	delete(descriptor, "data")
	delete(descriptor, "platform")
	delete(descriptor, "artifactType")
	delete(targetArtifactMap, "targetArtifact")

	unknownAttributes := append(getKeySet(descriptor), getKeySet(targetArtifactMap)...)
	return unknownAttributes
}

func getKeySet(inputMap map[string]interface{}) []string {
	keySet := make([]string, 0, len(inputMap))
	for k := range inputMap {
		keySet = append(keySet, k)
	}
	return keySet
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
	keyID        string
	pluginConfig map[string]string
	keySpec      signature.KeySpec
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

	req := &plugin.GenerateSignatureRequest{
		KeyID:        s.keyID,
		KeySpec:      keySpec,
		Hash:         keySpecHash,
		Payload:      payload,
		PluginConfig: s.pluginConfig,
	}

	resp, err := s.plugin.GenerateSignature(s.ctx, req)
	if err != nil {
		return nil, nil, err
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
