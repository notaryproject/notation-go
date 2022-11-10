// Package Verifier provides an implementation of notation.Verifier interface
package verifier

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/internal/envelope"
	"github.com/notaryproject/notation-go/internal/plugin"
	"github.com/notaryproject/notation-go/internal/plugin/manager"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// verifier implements notation.Verifier
type verifier struct {
	trustPolicyDoc *trustpolicy.Document
	pluginManager  pluginManager
}

// pluginManager is for mocking in unit tests
type pluginManager interface {
	Get(ctx context.Context, name string) (*manager.Plugin, error)
	Runner(name string) (plugin.Runner, error)
}

// New a verifier based on local file system
func New() (notation.Verifier, error) {
	// load trust policy
	policyDocument, err := loadPolicyDocument()
	if err != nil {
		return nil, err
	}
	return NewVerifier(policyDocument, manager.New(dir.PluginFS()))
}

// NewVerifier creates a new verifier given trustPolicy and pluginManager
func NewVerifier(trustPolicy *trustpolicy.Document, pluginManager *manager.Manager) (notation.Verifier, error) {
	if err := trustPolicy.Validate(); err != nil {
		return nil, err
	}
	return &verifier{
		trustPolicyDoc: trustPolicy,
		pluginManager:  pluginManager,
	}, nil
}

// Verify verifies the signature blob and returns the verified descriptor
// upon successful verification.
func (v *verifier) Verify(ctx context.Context, signature []byte, opts notation.VerifyOptions) (ocispec.Descriptor, *notation.VerificationOutcome, error) {
	artifactRef := opts.ArtifactReference
	envelopeMediaType := opts.SignatureMediaType
	pluginConfig := opts.PluginConfig

	trustPolicy, err := v.trustPolicyDoc.GetApplicableTrustPolicy(artifactRef)
	if err != nil {
		return ocispec.Descriptor{}, nil, notation.ErrorNoApplicableTrustPolicy{Msg: err.Error()}
	}
	// ignore the error since we already validated the policy document
	verificationLevel, _ := trustPolicy.SignatureVerification.GetVerificationLevel()

	outcome := &notation.VerificationOutcome{
		VerificationResults: []*notation.ValidationResult{},
		VerificationLevel:   verificationLevel,
	}
	err = v.processSignature(ctx, signature, envelopeMediaType, trustPolicy, pluginConfig, outcome)
	if err != nil {
		outcome.Error = err
		return ocispec.Descriptor{}, outcome, err
	}

	payload := &envelope.Payload{}
	err = json.Unmarshal(outcome.EnvelopeContent.Payload.Content, payload)
	if err != nil {
		outcome.Error = err
		return ocispec.Descriptor{}, outcome, err
	}

	return payload.TargetArtifact, outcome, nil
}

func (v *verifier) processSignature(ctx context.Context, sigBlob []byte, envelopeMediaType string, trustPolicy *trustpolicy.TrustPolicy, pluginConfig map[string]string, outcome *notation.VerificationOutcome) error {

	// verify integrity first. notation will always verify integrity no matter what the signing scheme is
	envContent, integrityResult := v.verifyIntegrity(sigBlob, envelopeMediaType, outcome)
	outcome.EnvelopeContent = envContent
	outcome.VerificationResults = append(outcome.VerificationResults, integrityResult)
	if integrityResult.Error != nil {
		return integrityResult.Error
	}

	// check if we need to verify using a plugin
	var pluginCapabilities []plugin.Capability
	verificationPluginName, err := getVerificationPlugin(&outcome.EnvelopeContent.SignerInfo)
	// use plugin, but getPluginName returns an error
	if err != nil && err != errExtendedAttributeNotExist {
		return err
	}
	if err == nil {
		installedPlugin, err := v.pluginManager.Get(ctx, verificationPluginName)
		if err != nil {
			return notation.ErrorVerificationInconclusive{Msg: fmt.Sprintf("error while locating the verification plugin %q, make sure the plugin is installed successfully before verifying the signature. error: %s", verificationPluginName, err)}
		}

		if _, err := getVerificationPluginMinVersion(&outcome.EnvelopeContent.SignerInfo); err != nil && err != errExtendedAttributeNotExist {
			return notation.ErrorVerificationInconclusive{Msg: fmt.Sprintf("error while getting plugin minimum version, error: %s", err)}
		}
		// TODO verify the plugin's version is equal to or greater than `outcome.SignerInfo.SignedAttributes.HeaderVerificationPluginMinVersion`
		// https://github.com/notaryproject/notation-go/issues/102

		// filter the "verification" capabilities supported by the installed plugin
		for _, capability := range installedPlugin.Capabilities {
			if capability == plugin.CapabilityRevocationCheckVerifier || capability == plugin.CapabilityTrustedIdentityVerifier {
				pluginCapabilities = append(pluginCapabilities, capability)
			}
		}

		if len(pluginCapabilities) == 0 {
			return notation.ErrorVerificationInconclusive{Msg: fmt.Sprintf("digital signature requires plugin %q with signature verification capabilities (%q and/or %q) installed", verificationPluginName, plugin.CapabilityTrustedIdentityVerifier, plugin.CapabilityRevocationCheckVerifier)}
		}
	}

	// verify x509 trust store based authenticity
	authenticityResult := v.verifyAuthenticity(ctx, trustPolicy, outcome)
	outcome.VerificationResults = append(outcome.VerificationResults, authenticityResult)
	if isCriticalFailure(authenticityResult) {
		return authenticityResult.Error
	}

	// verify x509 trusted identity based authenticity (only if notation needs to perform this verification rather than a plugin)
	if !plugin.CapabilityTrustedIdentityVerifier.In(pluginCapabilities) {
		v.verifyX509TrustedIdentities(trustPolicy, outcome, authenticityResult)
		if isCriticalFailure(authenticityResult) {
			return authenticityResult.Error
		}
	}

	// verify expiry
	expiryResult := v.verifyExpiry(outcome)
	outcome.VerificationResults = append(outcome.VerificationResults, expiryResult)
	if isCriticalFailure(expiryResult) {
		return expiryResult.Error
	}

	// verify authentic timestamp
	authenticTimestampResult := v.verifyAuthenticTimestamp(outcome)
	outcome.VerificationResults = append(outcome.VerificationResults, authenticTimestampResult)
	if isCriticalFailure(authenticTimestampResult) {
		return authenticTimestampResult.Error
	}

	// verify revocation
	// check if we need to bypass the revocation check, since revocation can be skipped using a trust policy or a plugin may override the check
	if outcome.VerificationLevel.Enforcement[trustpolicy.TypeRevocation] != trustpolicy.ActionSkip &&
		!plugin.CapabilityRevocationCheckVerifier.In(pluginCapabilities) {
		// TODO perform X509 revocation check (not in RC1)
		// https://github.com/notaryproject/notation-go/issues/110
	}

	// perform extended verification using verification plugin if present
	if verificationPluginName != "" {
		var capabilitiesToVerify []plugin.VerificationCapability
		for _, pc := range pluginCapabilities {
			// skip the revocation capability if the trust policy is configured to skip it
			if outcome.VerificationLevel.Enforcement[trustpolicy.TypeRevocation] == trustpolicy.ActionSkip && pc == plugin.CapabilityRevocationCheckVerifier {
				continue
			}
			capabilitiesToVerify = append(capabilitiesToVerify, plugin.VerificationCapability(pc))
		}

		if len(capabilitiesToVerify) > 0 {
			response, err := v.executePlugin(ctx, trustPolicy, capabilitiesToVerify, outcome.EnvelopeContent, pluginConfig)
			if err != nil {
				return err
			}
			return v.processPluginResponse(capabilitiesToVerify, response, outcome)
		}
	}

	return nil
}

func (v *verifier) processPluginResponse(capabilitiesToVerify []plugin.VerificationCapability, response *plugin.VerifySignatureResponse, outcome *notation.VerificationOutcome) error {
	verificationPluginName, err := getVerificationPlugin(&outcome.EnvelopeContent.SignerInfo)
	if err != nil {
		return err
	}

	// verify all extended critical attributes are processed by the plugin
	for _, attr := range getNonPluginExtendedCriticalAttributes(&outcome.EnvelopeContent.SignerInfo) {
		if !isPresentAny(attr.Key, response.ProcessedAttributes) {
			return fmt.Errorf("extended critical attribute %q was not processed by the verification plugin %q (all extended critical attributes must be processed by the verification plugin)", attr.Key, verificationPluginName)
		}
	}

	for _, capability := range capabilitiesToVerify {
		pluginResult := response.VerificationResults[capability]
		if pluginResult == nil {
			// verification result is empty for this capability
			return notation.ErrorVerificationInconclusive{Msg: fmt.Sprintf("verification plugin %q failed to verify %q", verificationPluginName, capability)}
		}
		switch capability {
		case plugin.VerificationCapabilityTrustedIdentity:
			if !pluginResult.Success {
				// find the Authenticity VerificationResult that we already created during x509 trust store verification
				var authenticityResult *notation.ValidationResult
				for _, r := range outcome.VerificationResults {
					if r.Type == trustpolicy.TypeAuthenticity {
						authenticityResult = r
						break
					}
				}

				authenticityResult.Error = fmt.Errorf("trusted identify verification by plugin %q failed with reason %q", verificationPluginName, pluginResult.Reason)

				if isCriticalFailure(authenticityResult) {
					return authenticityResult.Error
				}
			}
		case plugin.VerificationCapabilityRevocationCheck:
			var revocationResult *notation.ValidationResult
			if !pluginResult.Success {
				revocationResult = &notation.ValidationResult{
					Error:  fmt.Errorf("revocation check by verification plugin %q failed with reason %q", verificationPluginName, pluginResult.Reason),
					Type:   trustpolicy.TypeRevocation,
					Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeRevocation],
				}
			} else {
				revocationResult = &notation.ValidationResult{
					Type:   trustpolicy.TypeRevocation,
					Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeRevocation],
				}
			}
			outcome.VerificationResults = append(outcome.VerificationResults, revocationResult)
			if isCriticalFailure(revocationResult) {
				return revocationResult.Error
			}
		}
	}

	return nil
}
