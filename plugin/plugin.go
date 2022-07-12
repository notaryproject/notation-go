package plugin

import (
	"context"

	"github.com/notaryproject/notation-core-go/signer"
)

// Prefix is the prefix required on all plugin binary names.
const Prefix = "notation-"

// ContractVersion is the <major>.<minor> version of the plugin contract.
const ContractVersion = "1.0"

// Command is a CLI command available in the plugin contract.
type Command string

const (
	// CommandGetMetadata is the name of the plugin command
	// which must be supported by every plugin and returns the
	// plugin metadata.
	CommandGetMetadata Command = "get-plugin-metadata"

	// CommandDescribeKey is the name of the plugin command
	// which must be supported by every plugin that has the
	// SIGNATURE_GENERATOR capability.
	CommandDescribeKey Command = "describe-key"

	// CommandGenerateSignature is the name of the plugin command
	// which must be supported by every plugin that has the
	// SIGNATURE_GENERATOR capability.
	CommandGenerateSignature Command = "generate-signature"

	// CommandGenerateEnvelope is the name of the plugin command
	// which must be supported by every plugin that has the
	// SIGNATURE_ENVELOPE_GENERATOR capability.
	CommandGenerateEnvelope Command = "generate-envelope"
)

// Capability is a feature available in the plugin contract.
type Capability string

const (
	// CapabilitySignatureGenerator is the name of the capability
	// which should support a plugin to support generating signatures.
	CapabilitySignatureGenerator Capability = "SIGNATURE_GENERATOR"

	// CapabilityEnvelopeGenerator is the name of the capability
	// which should support a plugin to support generating envelope signatures.
	CapabilityEnvelopeGenerator Capability = "SIGNATURE_ENVELOPE_GENERATOR"
)

// GetMetadataRequest contains the parameters passed in a get-plugin-metadata request.
type GetMetadataRequest struct{}

func (GetMetadataRequest) Command() Command {
	return CommandGetMetadata
}

// DescribeKeyRequest contains the parameters passed in a describe-key request.
type DescribeKeyRequest struct {
	ContractVersion string            `json:"contractVersion"`
	KeyID           string            `json:"keyId"`
	PluginConfig    map[string]string `json:"pluginConfig,omitempty"`
}

func (DescribeKeyRequest) Command() Command {
	return CommandDescribeKey
}

// DescribeKeyResponse is the response of a describe-key request.
type DescribeKeyResponse struct {
	// The same key id as passed in the request.
	KeyID string `json:"keyId"`

	// One of following supported key types:
	// https://github.com/notaryproject/notaryproject/blob/main/signature-specification.md#algorithm-selection
	KeySpec signer.KeySpec `json:"keySpec"`
}

// GenerateSignatureRequest contains the parameters passed in a generate-signature request.
type GenerateSignatureRequest struct {
	ContractVersion string                 `json:"contractVersion"`
	KeyID           string                 `json:"keyId"`
	KeySpec         signer.KeySpec         `json:"keySpec"`
	Hash            string                 `json:"hashAlgorithm"`
	Payload         []byte                 `json:"payload"`
	PluginConfig    map[string]string      `json:"pluginConfig,omitempty"`
}

func (GenerateSignatureRequest) Command() Command {
	return CommandGenerateSignature
}

// GenerateSignatureResponse is the response of a generate-signature request.
type GenerateSignatureResponse struct {
	KeyID            string                      `json:"keyId"`
	Signature        []byte                      `json:"signature"`
	SigningAlgorithm signer.SignatureAlgorithm   `json:"signingAlgorithm"`

	// Ordered list of certificates starting with leaf certificate
	// and ending with root certificate.
	CertificateChain [][]byte `json:"certificateChain"`
}

// GenerateEnvelopeRequest contains the parameters passed in a generate-envelope request.
type GenerateEnvelopeRequest struct {
	ContractVersion       string            `json:"contractVersion"`
	KeyID                 string            `json:"keyId"`
	PayloadType           string            `json:"payloadType"`
	SignatureEnvelopeType string            `json:"signatureEnvelopeType"`
	Payload               []byte            `json:"payload"`
	PluginConfig          map[string]string `json:"pluginConfig,omitempty"`
}

func (GenerateEnvelopeRequest) Command() Command {
	return CommandGenerateEnvelope
}

// GenerateEnvelopeResponse is the response of a generate-envelope request.
type GenerateEnvelopeResponse struct {
	SignatureEnvelope     []byte            `json:"signatureEnvelope"`
	SignatureEnvelopeType string            `json:"signatureEnvelopeType"`
	Annotations           map[string]string `json:"annotations,omitempty"`
}

// Request defines a plugin request, which is always associated to a command.
type Request interface {
	Command() Command
}

// Runner is an interface for running commands against a plugin.
type Runner interface {
	// Run executes the specified command and waits for it to complete.
	//
	// When the returned object is not nil, its type is guaranteed to remain always the same for a given Command.
	//
	// The returned error is nil if:
	// - the plugin exists
	// - the command runs and exits with a zero exit status
	// - the command stdout contains a valid json object which can be unmarshal-ed.
	//
	// If the command starts but does not complete successfully, the error is of type RequestError wrapping a *exec.ExitError.
	// Other error types may be returned for other situations.
	Run(ctx context.Context, req Request) (interface{}, error)
}
