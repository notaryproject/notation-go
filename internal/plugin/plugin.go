package plugin

import (
	"context"

	"github.com/notaryproject/notation-go/plugin/proto"
)

// Prefix is the prefix required on all plugin binary names.
const Prefix = proto.Prefix

// ContractVersion is the <major>.<minor> version of the plugin contract.
const ContractVersion = proto.ContractVersion

// Command is a CLI command available in the plugin contract.
type Command = proto.Command

const (
	// CommandGetMetadata is the name of the plugin command
	// which must be supported by every plugin and returns the
	// plugin metadata.
	CommandGetMetadata Command = proto.CommandGetMetadata

	// CommandDescribeKey is the name of the plugin command
	// which must be supported by every plugin that has the
	// SIGNATURE_GENERATOR.RAW capability.
	CommandDescribeKey Command = proto.CommandDescribeKey

	// CommandGenerateSignature is the name of the plugin command
	// which must be supported by every plugin that has the
	// SIGNATURE_GENERATOR.RAW capability.
	CommandGenerateSignature Command = proto.CommandGenerateSignature

	// CommandGenerateEnvelope is the name of the plugin command
	// which must be supported by every plugin that has the
	// SIGNATURE_GENERATOR.ENVELOPE capability.
	CommandGenerateEnvelope Command = proto.CommandGenerateEnvelope

	// CommandVerifySignature is the name of the plugin command
	// which must be supported by every plugin that has
	// any SIGNATURE_VERIFIER.* capability
	CommandVerifySignature Command = proto.CommandVerifySignature
)

// Capability is a feature available in the plugin contract.
type Capability = proto.Capability

const (
	// CapabilitySignatureGenerator is the name of the capability
	// for a plugin to support generating raw signatures.
	CapabilitySignatureGenerator Capability = proto.CapabilitySignatureGenerator

	// CapabilityEnvelopeGenerator is the name of the capability
	// for a plugin to support generating envelope signatures.
	CapabilityEnvelopeGenerator Capability = proto.CapabilityEnvelopeGenerator

	// CapabilityTrustedIdentityVerifier is the name of the capability
	// for a plugin to support verifying trusted identities.
	CapabilityTrustedIdentityVerifier = Capability(VerificationCapabilityTrustedIdentity)

	// CapabilityRevocationCheckVerifier is the name of the capability
	// for a plugin to support verifying revocation checks.
	CapabilityRevocationCheckVerifier = Capability(VerificationCapabilityRevocationCheck)
)

// VerificationCapability is a verification feature available in the plugin contract.
type VerificationCapability string

const (
	// VerificationCapabilityTrustedIdentity is the name of the capability
	// for a plugin to support verifying trusted identities.
	VerificationCapabilityTrustedIdentity VerificationCapability = VerificationCapability(proto.CapabilityTrustedIdentityVerifier)

	// VerificationCapabilityRevocationCheck is the name of the capability
	// for a plugin to support verifying revocation checks.
	VerificationCapabilityRevocationCheck VerificationCapability = VerificationCapability(proto.CapabilityRevocationCheckVerifier)
)

// GetMetadataRequest contains the parameters passed in a get-plugin-metadata request.
type GetMetadataRequest = proto.GetMetadataRequest

// DescribeKeyRequest contains the parameters passed in a describe-key request.
type DescribeKeyRequest = proto.DescribeKeyRequest

// DescribeKeyResponse is the response of a describe-key request.
type DescribeKeyResponse = proto.DescribeKeyResponse

// GenerateSignatureRequest contains the parameters passed in a generate-signature request.
type GenerateSignatureRequest = proto.GenerateSignatureRequest

// GenerateSignatureResponse is the response of a generate-signature request.
type GenerateSignatureResponse = proto.GenerateSignatureResponse

// GenerateEnvelopeRequest contains the parameters passed in a generate-envelope request.
type GenerateEnvelopeRequest = proto.GenerateEnvelopeRequest

// GenerateEnvelopeResponse is the response of a generate-envelope request.
type GenerateEnvelopeResponse = proto.GenerateEnvelopeResponse

// VerifySignatureRequest contains the parameters passed in a verify-signature request.
type VerifySignatureRequest struct {
	ContractVersion string            `json:"contractVersion"`
	Signature       Signature         `json:"signature"`
	TrustPolicy     TrustPolicy       `json:"trustPolicy"`
	PluginConfig    map[string]string `json:"pluginConfig,omitempty"`
}

func (VerifySignatureRequest) Command() Command {
	return CommandVerifySignature
}

// Signature represents a signature pulled from the envelope
type Signature = proto.Signature

// CriticalAttributes contains all Notary V2 defined critical
// attributes and their values in the signature envelope
type CriticalAttributes = proto.CriticalAttributes

// TrustPolicy represents trusted identities that sign the artifacts
type TrustPolicy struct {
	TrustedIdentities     []string                 `json:"trustedIdentities"`
	SignatureVerification []VerificationCapability `json:"signatureVerification"`
}

// VerifySignatureResponse is the response of a verify-signature request.
type VerifySignatureResponse struct {
	VerificationResults map[VerificationCapability]*VerificationResult `json:"verificationResults"`
	ProcessedAttributes []interface{}                                  `json:"processedAttributes"`
}

// VerificationResult is the result of a verification performed by the plugin
type VerificationResult = proto.VerificationResult

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
