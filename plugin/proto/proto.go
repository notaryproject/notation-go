package proto

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
	// SIGNATURE_GENERATOR.RAW capability.
	CommandDescribeKey Command = "describe-key"

	// CommandGenerateSignature is the name of the plugin command
	// which must be supported by every plugin that has the
	// SIGNATURE_GENERATOR.RAW capability.
	CommandGenerateSignature Command = "generate-signature"

	// CommandGenerateEnvelope is the name of the plugin command
	// which must be supported by every plugin that has the
	// SIGNATURE_GENERATOR.ENVELOPE capability.
	CommandGenerateEnvelope Command = "generate-envelope"

	// CommandVerifySignature is the name of the plugin command
	// which must be supported by every plugin that has
	// any SIGNATURE_VERIFIER.* capability
	CommandVerifySignature Command = "verify-signature"
)

// Request defines a plugin request, which is always associated to a command.
type Request interface {
	Command() Command
}

// Capability is a feature available in the plugin contract.
type Capability string

const (
	// CapabilitySignatureGenerator is the name of the capability
	// for a plugin to support generating raw signatures.
	CapabilitySignatureGenerator Capability = "SIGNATURE_GENERATOR.RAW"

	// CapabilityEnvelopeGenerator is the name of the capability
	// for a plugin to support generating envelope signatures.
	CapabilityEnvelopeGenerator Capability = "SIGNATURE_GENERATOR.ENVELOPE"
)

// In returns true if the Capability is present in the given array of
// capabilities.
func (c Capability) In(capabilities []Capability) bool {
	for _, capability := range capabilities {
		if c == capability {
			return true
		}
	}
	return false
}

// VerificationCapability is feature for verification in the plugin contract.
type VerificationCapability Capability

const (
	// VerificationCapabilityTrustedIdentityVerifier is the name of the
	// capability for a plugin to support verifying trusted identities.
	VerificationCapabilityTrustedIdentityVerifier VerificationCapability = "SIGNATURE_VERIFIER.TRUSTED_IDENTITY"

	// VerificationCapabilityRevocationCheckVerifier is the name of the
	// capability for a plugin to support verifying revocation checks.
	VerificationCapabilityRevocationCheckVerifier VerificationCapability = "SIGNATURE_VERIFIER.REVOCATION_CHECK"
)

// In returns true if the Capability is present in the given array of
// capabilities.
func (c VerificationCapability) In(capabilities []Capability) bool {
	for _, capability := range capabilities {
		if Capability(c) == capability {
			return true
		}
	}
	return false
}
