package proto

import "time"

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
type Signature struct {
	CriticalAttributes    CriticalAttributes `json:"criticalAttributes"`
	UnprocessedAttributes []interface{}      `json:"unprocessedAttributes"`
	CertificateChain      [][]byte           `json:"certificateChain"`
}

// CriticalAttributes contains all Notary V2 defined critical
// attributes and their values in the signature envelope
type CriticalAttributes struct {
	ContentType          string                      `json:"contentType"`
	SigningScheme        string                      `json:"signingScheme"`
	Expiry               *time.Time                  `json:"expiry,omitempty"`
	AuthenticSigningTime *time.Time                  `json:"authenticSigningTime,omitempty"`
	ExtendedAttributes   map[interface{}]interface{} `json:"extendedAttributes,omitempty"`
}

// TrustPolicy represents trusted identities that sign the artifacts
type TrustPolicy struct {
	TrustedIdentities     []string     `json:"trustedIdentities"`
	SignatureVerification []Capability `json:"signatureVerification"`
}

// VerifySignatureResponse is the response of a verify-signature request.
type VerifySignatureResponse struct {
	VerificationResults map[Capability]*VerificationResult `json:"verificationResults"`
	ProcessedAttributes []interface{}                      `json:"processedAttributes"`
}

// VerificationResult is the result of a verification performed by the plugin
type VerificationResult struct {
	Success bool   `json:"success"`
	Reason  string `json:"reason,omitempty"`
}
