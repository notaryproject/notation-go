package plugin

import (
	"context"
	"time"
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

// Capability is a feature available in the plugin contract.
type Capability string

// In returns true if the Capability is present in the given array of capabilities
func (c Capability) In(capabilities []Capability) bool {
	for _, capability := range capabilities {
		if c == capability {
			return true
		}
	}
	return false
}

const (
	// CapabilitySignatureGenerator is the name of the capability
	// for a plugin to support generating raw signatures.
	CapabilitySignatureGenerator Capability = "SIGNATURE_GENERATOR.RAW"

	// CapabilityEnvelopeGenerator is the name of the capability
	// for a plugin to support generating envelope signatures.
	CapabilityEnvelopeGenerator Capability = "SIGNATURE_GENERATOR.ENVELOPE"

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
	VerificationCapabilityTrustedIdentity VerificationCapability = "SIGNATURE_VERIFIER.TRUSTED_IDENTITY"

	// VerificationCapabilityRevocationCheck is the name of the capability
	// for a plugin to support verifying revocation checks.
	VerificationCapabilityRevocationCheck VerificationCapability = "SIGNATURE_VERIFIER.REVOCATION_CHECK"
)

// SigningScheme formalizes the feature set provided by the signature produced using a signing scheme
type SigningScheme string

const (
	// SigningSchemeDefault defines a signing scheme that uses the traditional signing workflow
	// in which an end user generates signatures using X.509 certificates
	SigningSchemeDefault SigningScheme = "notary.default.x509"

	// SigningSchemeAuthority defines a signing scheme in which a signing authority
	// generates signatures on behalf of an end user using X.509 certificates
	SigningSchemeAuthority SigningScheme = "notary.signingAuthority.x509"
)

// GetMetadataRequest contains the parameters passed in a get-plugin-metadata request.
type GetMetadataRequest struct {
	PluginConfig map[string]string `json:"pluginConfig,omitempty"`
}

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
	KeySpec string `json:"keySpec"`
}

// GenerateSignatureRequest contains the parameters passed in a generate-signature request.
type GenerateSignatureRequest struct {
	ContractVersion string            `json:"contractVersion"`
	KeyID           string            `json:"keyId"`
	KeySpec         string            `json:"keySpec"`
	Hash            string            `json:"hashAlgorithm"`
	Payload         []byte            `json:"payload"`
	PluginConfig    map[string]string `json:"pluginConfig,omitempty"`
}

func (GenerateSignatureRequest) Command() Command {
	return CommandGenerateSignature
}

// GenerateSignatureResponse is the response of a generate-signature request.
type GenerateSignatureResponse struct {
	KeyID            string `json:"keyId"`
	Signature        []byte `json:"signature"`
	SigningAlgorithm string `json:"signingAlgorithm"`

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

// VerifySignatureRequest contains the parameters passed in a verify-signature request.
type VerifySignatureRequest struct {
	ContractVersion string            `json:"contractVersion"`
	Signature       Signature         `json:"signature"`
	TrustPolicy     TrustPolicy       `json:"trustPolicy"`
	PluginConfig    map[string]string `json:"pluginConfig,omitempty"`
}

// Signature represents a signature pulled from the envelope
type Signature struct {
	CriticalAttributes    CriticalAttributes `json:"criticalAttributes"`
	UnprocessedAttributes []string           `json:"unprocessedAttributes"`
	CertificateChain      [][]byte           `json:"certificateChain"`
}

// CriticalAttributes contains all Notary V2 defined critical
// attributes and their values in the signature envelope
type CriticalAttributes struct {
	ContentType          string                 `json:"contentType"`
	SigningScheme        string                 `json:"signingScheme"`
	Expiry               *time.Time             `json:"expiry,omitempty"`
	AuthenticSigningTime *time.Time             `json:"authenticSigningTime,omitempty"`
	ExtendedAttributes   map[string]interface{} `json:"extendedAttributes,omitempty"`
}

// TrustPolicy represents trusted identities that sign the artifacts
type TrustPolicy struct {
	TrustedIdentities     []string                 `json:"trustedIdentities"`
	SignatureVerification []VerificationCapability `json:"signatureVerification"`
}

func (VerifySignatureRequest) Command() Command {
	return CommandVerifySignature
}

// VerifySignatureResponse is the response of a verify-signature request.
type VerifySignatureResponse struct {
	VerificationResults map[VerificationCapability]*VerificationResult `json:"verificationResults"`
	ProcessedAttributes []interface{}                                  `json:"processedAttributes"`
}

// VerificationResult is the result of a verification performed by the plugin
type VerificationResult struct {
	Success bool   `json:"success"`
	Reason  string `json:"reason,omitempty"`
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
