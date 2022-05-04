package plugin

import (
	"crypto"
)

// Prefix is the prefix required on all plugin binary names.
const Prefix = "notation-"

// KeySpec defines a key type and size.
type KeySpec string

// One of following supported specs
// https://github.com/notaryproject/notaryproject/blob/main/signature-specification.md#algorithm-selection
const (
	RSA_2048 KeySpec = "RSA_2048"
	RSA_3072 KeySpec = "RSA_3072"
	RSA_4096 KeySpec = "RSA_4096"
	EC_256   KeySpec = "EC_256"
	EC_384   KeySpec = "EC_384"
	EC_512   KeySpec = "EC_512"
)

// HashFunc returns the Hash associated k.
func (k KeySpec) HashFunc() crypto.Hash {
	switch k {
	case RSA_2048, EC_256:
		return crypto.SHA256
	case RSA_3072, EC_384:
		return crypto.SHA384
	case RSA_4096, EC_512:
		return crypto.SHA512
	}
	return crypto.Hash(0)
}

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

// DescribeKeyRequest contains the parameters passed in a describe-key request.
// All parameters are required.
type DescribeKeyRequest struct {
	ContractVersion string            `json:"contractVersion"`
	KeyName         string            `json:"keyName"`
	KeyID           string            `json:"keyId"`
	PluginConfig    map[string]string `json:"pluginConfig"`
}

// GenerateSignatureResponse is the response of a describe-key request.
type DescribeKeyResponse struct {
	// The same key id as passed in the request.
	KeyID string `json:"keyId"`

	// One of following supported key types:
	// https://github.com/notaryproject/notaryproject/blob/main/signature-specification.md#algorithm-selection
	KeySpec KeySpec `json:"keySpec"`
}

// GenerateSignatureRequest contains the parameters passed in a generate-signature request.
// All parameters are required.
type GenerateSignatureRequest struct {
	ContractVersion string `json:"contractVersion"`
	KeyName         string `json:"keyName"`
	KeyID           string `json:"keyId"`
	Payload         string `json:"payload"`
}

// GenerateSignatureResponse is the response of a generate-signature request.
type GenerateSignatureResponse struct {
	// The same key id as passed in the request.
	KeyID string `json:"keyId"`

	// Base64 encoded signature.
	Signature string `json:"signature"`

	// One of following supported signing algorithms:
	// https://github.com/notaryproject/notaryproject/blob/main/signature-specification.md#algorithm-selection
	SigningAlgorithm string `json:"signingAlgorithm"`

	// Ordered list of certificates starting with leaf certificate
	// and ending with root certificate.
	CertificateChain []string `json:"certificateChain"`
}

// GenerateEnvelopeRequest contains the parameters passed in a generate-envelop request.
// All parameters are required.
type GenerateEnvelopeRequest struct {
	ContractVersion       string `json:"contractVersion"`
	KeyName               string `json:"keyName"`
	KeyID                 string `json:"keyId"`
	PayloadType           string `json:"payloadType"`
	SignatureEnvelopeType string `json:"signatureEnvelopeType"`
	Payload               string `json:"payload"`
}

// GenerateSignatureResponse is the response of a generate-envelop request.
type GenerateEnvelopeResponse struct {
	// Base64 encoded signature envelope.
	SignatureEnvelope string `json:"signatureEnvelope"`

	// The media type of the envelope of notation signature.
	SignatureEnvelopeType string `json:"signatureEnvelopeType"`

	// Annotations to be appended to Signature Manifest annotations.
	Annotations map[string]string `json:"annotations,omitempty"`
}
