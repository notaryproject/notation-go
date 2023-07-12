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
	// https://github.com/notaryproject/notaryproject/blob/main/specs/signature-specification.md#algorithm-selection
	KeySpec KeySpec `json:"keySpec"`
}

// GenerateSignatureRequest contains the parameters passed in a
// generate-signature request.
type GenerateSignatureRequest struct {
	ContractVersion string            `json:"contractVersion"`
	KeyID           string            `json:"keyId"`
	KeySpec         KeySpec           `json:"keySpec"`
	Hash            HashAlgorithm     `json:"hashAlgorithm"`
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
	ContractVersion         string            `json:"contractVersion"`
	KeyID                   string            `json:"keyId"`
	PayloadType             string            `json:"payloadType"`
	SignatureEnvelopeType   string            `json:"signatureEnvelopeType"`
	Payload                 []byte            `json:"payload"`
	ExpiryDurationInSeconds uint64            `json:"expiryDurationInSeconds,omitempty"`
	PluginConfig            map[string]string `json:"pluginConfig,omitempty"`
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
