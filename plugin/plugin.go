package plugin

import (
	"errors"
)

// NamePrefix is the prefix required on all plugin binary names.
const NamePrefix = "notation-"

// Command is a CLI command available in the plugin contract.
type Command string

const (
	// CommandGetMetadata is the name of the plugin command
	// which must be supported by every plugin and returns the
	// plugin metadata.
	CommandGetMetadata Command = "get-plugin-metadata"

	// CommandGenerateSignature is the name of the plugin command
	// which must be supported by every plugin that has the
	// SIGNATURE_GENERATOR capability.
	CommandGenerateSignature Command = "generate-signature"

	// CommandGenerateEnvelope is the name of the plugin command
	// which must be supported by every plugin that has the
	// SIGNATURE_ENVELOPE_GENERATOR capability.
	CommandGenerateEnvelope Command = "generate-envelope"
)

// Capability returns the capability associated to the command.
func (c Command) Capability() Capability {
	switch c {
	case CommandGenerateSignature:
		return CapabilitySignatureGenerator
	case CommandGenerateEnvelope:
		return CapabilityEnvelopeGenerator
	default:
		return ""
	}
}

// Capability returns the response associated to the command.
func (c Command) NewResponse() interface{} {
	switch c {
	case CommandGetMetadata:
		return new(Metadata)
	case CommandGenerateSignature:
		return new(GenerateSignatureResponse)
	case CommandGenerateEnvelope:
		return new(GenerateEnvelopeResponse)
	default:
		return nil
	}
}

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

// Command line argument names used in several requests.
const (
	ArgContractVersion       = "--contract-version"
	ArgKeyName               = "--key-name"
	ArgKeyID                 = "--key-id"
	ArgPayloadType           = "--payload-type"
	ArgSignatureEnvelopeType = "--signature-envelop-type"
)

// GenerateSignatureRequest contains the parameters passed in a generate-signature request.
// All parameters are required.
type GenerateSignatureRequest struct {
	ContractVersion string
	KeyName         string
	KeyID           string
}

func (req *GenerateSignatureRequest) Command() Command {
	return CommandGenerateSignature
}

func (req *GenerateSignatureRequest) Args() []string {
	return []string{
		ArgContractVersion, req.ContractVersion,
		ArgKeyName, req.KeyName,
		ArgKeyID, req.KeyID,
	}
}

func (req *GenerateSignatureRequest) Validate() error {
	if req == nil {
		return errors.New("nil request")
	}
	if req.ContractVersion == "" {
		return errors.New("empty contractVersion")
	}
	if req.KeyName == "" {
		return errors.New("empty keyName")
	}
	if req.KeyID == "" {
		return errors.New("empty keyId")
	}
	return nil
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
	ContractVersion       string
	KeyName               string
	KeyID                 string
	PayloadType           string
	SignatureEnvelopeType string
}

func (req *GenerateEnvelopeRequest) Command() Command {
	return CommandGenerateEnvelope
}

func (req *GenerateEnvelopeRequest) Args() []string {
	return []string{
		ArgContractVersion, req.ContractVersion,
		ArgKeyName, req.KeyName,
		ArgKeyID, req.KeyID,
		ArgPayloadType, req.PayloadType,
		ArgSignatureEnvelopeType, req.SignatureEnvelopeType,
	}
}

func (req *GenerateEnvelopeRequest) Validate() error {
	if req == nil {
		return errors.New("nil request")
	}
	if req.ContractVersion == "" {
		return errors.New("empty contractVersion")
	}
	if req.KeyName == "" {
		return errors.New("empty keyName")
	}
	if req.KeyID == "" {
		return errors.New("empty keyId")
	}
	if req.PayloadType == "" {
		return errors.New("empty payloadType")
	}
	if req.SignatureEnvelopeType == "" {
		return errors.New("empty envelopeType")
	}
	return nil
}

// GenerateSignatureResponse is the response of a generate-envelop request.
type GenerateEnvelopeResponse struct {
	// Base64 encoded signature envelope.
	SignatureEnvelope string `json:"signatureEnvelope"`

	SignatureEnvelopeType string `json:"signatureEnvelopeType"`

	// Annotations to be appended to Signature Manifest annotations.
	Annotations map[string]string `json:"annotations,omitempty"`
}
