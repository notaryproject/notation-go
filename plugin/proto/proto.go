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

// Package proto defines the protocol layer for communication between notation
// and notation external plugin.
package proto

import "github.com/notaryproject/notation-plugin-framework-go/plugin"

// Prefix is the prefix required on all plugin binary names.
//
// Deprecated: Prefix exists for historical compatibility and should not be used.
// To access Prefix, use the notation-plugin-framework-go's [plugin.BinaryPrefix] type.
const Prefix = plugin.BinaryPrefix

// ContractVersion is the <major>.<minor> version of the plugin contract.
//
// Deprecated: ContractVersion exists for historical compatibility and should not be used.
// To access ContractVersion, use the notation-plugin-framework-go's [plugin.ContractVersion] type.
const ContractVersion = plugin.ContractVersion

// Command is a CLI command available in the plugin contract.
//
// Deprecated: Command exists for historical compatibility and should not be used.
// To access Command, use the notation-plugin-framework-go's [plugin.Command] type.
type Command = plugin.Command

// Request defines a plugin request, which is always associated to a command.
//
// Deprecated: Request exists for historical compatibility and should not be used.
// To access Request, use the notation-plugin-framework-go's [plugin.Request] type.
type Request = plugin.Request

const (
	// CommandGetMetadata is the name of the plugin command
	// which must be supported by every plugin and returns the
	// plugin metadata.
	//
	// Deprecated: CommandGetMetadata exists for historical compatibility and should not be used.
	// To access CommandGetMetadata, use the notation-plugin-framework-go's [plugin.CommandGetMetadata].
	CommandGetMetadata = plugin.CommandGetMetadata

	// CommandDescribeKey is the name of the plugin command
	// which must be supported by every plugin that has the
	// SIGNATURE_GENERATOR.RAW capability.
	//
	// Deprecated: CommandDescribeKey exists for historical compatibility and should not be used.
	// To access CommandDescribeKey, use the notation-plugin-framework-go's [plugin.CommandDescribeKey].
	CommandDescribeKey = plugin.CommandDescribeKey

	// CommandGenerateSignature is the name of the plugin command
	// which must be supported by every plugin that has the
	// SIGNATURE_GENERATOR.RAW capability.
	//
	// Deprecated: CommandGenerateSignature exists for historical compatibility and should not be used.
	// To access CommandGenerateSignature, use the notation-plugin-framework-go's [plugin.CommandGenerateSignature].
	CommandGenerateSignature = plugin.CommandGenerateSignature

	// CommandGenerateEnvelope is the name of the plugin command
	// which must be supported by every plugin that has the
	// SIGNATURE_GENERATOR.ENVELOPE capability.
	//
	// Deprecated: CommandGenerateEnvelope exists for historical compatibility and should not be used.
	// To access CommandGenerateEnvelope, use the notation-plugin-framework-go's [plugin.CommandGenerateEnvelope].
	CommandGenerateEnvelope = plugin.CommandGenerateEnvelope

	// CommandVerifySignature is the name of the plugin command
	// which must be supported by every plugin that has
	// any SIGNATURE_VERIFIER.* capability
	//
	// Deprecated: CommandVerifySignature exists for historical compatibility and should not be used.
	// To access CommandVerifySignature, use the notation-plugin-framework-go's [plugin.CommandVerifySignature].
	CommandVerifySignature = plugin.CommandVerifySignature
)

// Capability is a feature available in the plugin contract.
//
// Deprecated: Capability exists for historical compatibility and should not be used.
// To access Capability, use the notation-plugin-framework-go's [plugin.Capability] type.
type Capability = plugin.Capability

const (
	// CapabilitySignatureGenerator is the name of the capability
	// for a plugin to support generating raw signatures.
	//
	// Deprecated: CapabilitySignatureGenerator exists for historical compatibility and should not be used.
	// To access CapabilitySignatureGenerator, use the notation-plugin-framework-go's [plugin.CapabilitySignatureGenerator].
	CapabilitySignatureGenerator = plugin.CapabilitySignatureGenerator

	// CapabilityEnvelopeGenerator is the name of the capability
	// for a plugin to support generating envelope signatures.
	//
	// Deprecated: CapabilityEnvelopeGenerator exists for historical compatibility and should not be used.
	// To access CapabilityEnvelopeGenerator, use the notation-plugin-framework-go's [plugin.CapabilityEnvelopeGenerator].
	CapabilityEnvelopeGenerator = plugin.CapabilityEnvelopeGenerator

	// CapabilityTrustedIdentityVerifier is the name of the
	// capability for a plugin to support verifying trusted identities.
	//
	// Deprecated: CapabilityTrustedIdentityVerifier exists for historical compatibility and should not be used.
	// To access CapabilityTrustedIdentityVerifier, use the notation-plugin-framework-go's [plugin.CapabilityTrustedIdentityVerifier].
	CapabilityTrustedIdentityVerifier = plugin.CapabilityTrustedIdentityVerifier

	// CapabilityRevocationCheckVerifier is the name of the
	// capability for a plugin to support verifying revocation checks.
	//
	// Deprecated: CapabilityRevocationCheckVerifier exists for historical compatibility and should not be used.
	// To access CapabilityRevocationCheckVerifier, use the notation-plugin-framework-go's [plugin.CapabilityRevocationCheckVerifier].
	CapabilityRevocationCheckVerifier = plugin.CapabilityRevocationCheckVerifier
)
