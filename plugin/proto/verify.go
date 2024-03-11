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

import (
	"github.com/notaryproject/notation-plugin-framework-go/plugin"
)

// VerifySignatureRequest contains the parameters passed in a verify-signature
// request.
//
// Deprecated: VerifySignatureRequest exists for historical compatibility and should not be used.
// To access VerifySignatureRequest, use the notation-plugin-framework-go'[s plugin.VerifySignatureRequest] type.
type VerifySignatureRequest = plugin.VerifySignatureRequest

// Signature represents a signature pulled from the envelope
//
// Deprecated: Signature exists for historical compatibility and should not be used.
// To access Signature, use the notation-plugin-framework-go's [plugin.Signature] type.
type Signature = plugin.Signature

// CriticalAttributes contains all Notary Project defined critical
// attributes and their values in the signature envelope
//
// Deprecated: CriticalAttributes exists for historical compatibility and should not be used.
// To access CriticalAttributes, use the notation-plugin-framework-go's [plugin.CriticalAttributes] type.
type CriticalAttributes = plugin.CriticalAttributes

// TrustPolicy represents trusted identities that sign the artifacts
//
// Deprecated: TrustPolicy exists for historical compatibility and should not be used.
// To access TrustPolicy, use the notation-plugin-framework-go's [plugin.TrustPolicy] type.
type TrustPolicy = plugin.TrustPolicy

// VerifySignatureResponse is the response of a verify-signature request.
//
// Deprecated: VerifySignatureResponse exists for historical compatibility and should not be used.
// To access VerifySignatureResponse, use the notation-plugin-framework-go's [plugin.VerifySignatureResponse] type.
type VerifySignatureResponse = plugin.VerifySignatureResponse

// VerificationResult is the result of a verification performed by the plugin.
//
// Deprecated: VerificationResult exists for historical compatibility and should not be used.
// To access VerificationResult, use the notation-plugin-framework-go's [plugin.VerificationResult] type.
type VerificationResult = plugin.VerificationResult
