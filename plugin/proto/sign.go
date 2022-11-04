package proto

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

// GenerateSignatureRequest contains the parameters passed in a
// generate-signature request.
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

// GenerateEnvelopeRequest contains the parameters passed in a generate-envelope
// request.
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

// SigningScheme formalizes the feature set provided by the signature produced
// using a signing scheme.
type SigningScheme string

const (
	// SigningSchemeDefault defines a signing scheme that uses the traditional
	// signing workflow in which an end user generates signatures using X.509
	// certificates.
	SigningSchemeDefault SigningScheme = "notary.default.x509"

	// SigningSchemeAuthority defines a signing scheme in which a signing
	// authority generates signatures on behalf of an end user using X.509
	// certificates.
	SigningSchemeAuthority SigningScheme = "notary.signingAuthority.x509"
)
