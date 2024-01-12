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

import "github.com/notaryproject/notation-plugin-framework-go/plugin"

// DescribeKeyRequest contains the parameters passed in a describe-key request.
type DescribeKeyRequest = plugin.DescribeKeyRequest

// DescribeKeyResponse is the response of a describe-key request.
type DescribeKeyResponse = plugin.DescribeKeyResponse

// GenerateSignatureRequest contains the parameters passed in a
// generate-signature request.
type GenerateSignatureRequest = plugin.GenerateSignatureRequest

// GenerateSignatureResponse is the response of a generate-signature request.
type GenerateSignatureResponse = plugin.GenerateSignatureResponse

// GenerateEnvelopeRequest contains the parameters passed in a generate-envelope
// request.
type GenerateEnvelopeRequest = plugin.GenerateEnvelopeRequest

// GenerateEnvelopeResponse is the response of a generate-envelope request.
type GenerateEnvelopeResponse = plugin.GenerateEnvelopeResponse
