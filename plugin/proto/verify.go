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
type VerifySignatureRequest = plugin.VerifySignatureRequest

// Signature represents a signature pulled from the envelope
type Signature = plugin.Signature

// CriticalAttributes contains all Notary Project defined critical
// attributes and their values in the signature envelope
type CriticalAttributes = plugin.CriticalAttributes

// TrustPolicy represents trusted identities that sign the artifacts
type TrustPolicy = plugin.TrustPolicy

// VerifySignatureResponse is the response of a verify-signature request.
type VerifySignatureResponse = plugin.VerifySignatureResponse

// VerificationResult is the result of a verification performed by the plugin
type VerificationResult = plugin.VerificationResult
