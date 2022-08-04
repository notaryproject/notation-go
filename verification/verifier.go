package verification

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/plugin"
	"github.com/notaryproject/notation-go/plugin/manager"
	"github.com/notaryproject/notation-go/registry"
	"reflect"
	"time"
)

type Verifier struct {
	PolicyDocument *PolicyDocument
	Repository     registry.Repository
	PathManager    *dir.PathManager
	PluginManager  pluginManager
}

// pluginManager is for mocking in unit tests
type pluginManager interface {
	Get(ctx context.Context, name string) (*manager.Plugin, error)
	Runner(name string) (plugin.Runner, error)
}

func NewVerifier(repository registry.Repository) (*Verifier, error) {
	// load trust policy
	policyDocument, err := loadPolicyDocument(dir.Path.TrustPolicy())
	if err != nil {
		return nil, err
	}
	if err = policyDocument.ValidatePolicyDocument(); err != nil {
		return nil, err
	}

	return &Verifier{
		PolicyDocument: policyDocument,
		Repository:     repository,
		PathManager:    dir.Path,
		PluginManager:  manager.New(),
	}, nil
}

/*
Verify performs verification for each of the verification types supported in notation
See https://github.com/notaryproject/notaryproject/blob/main/trust-store-trust-policy-specification.md#signature-verification
*/
func (v *Verifier) Verify(ctx context.Context, artifactUri string) ([]*SignatureVerificationOutcome, error) {
	var verificationOutcomes []*SignatureVerificationOutcome

	trustPolicy, err := v.PolicyDocument.getApplicableTrustPolicy(artifactUri)
	if err != nil {
		return nil, ErrorNoApplicableTrustPolicy{msg: err.Error()}
	}

	verificationLevel, _ := GetVerificationLevel(trustPolicy.SignatureVerification) // ignore the error since we already validated the policy document

	if verificationLevel.Name == Skip.Name {
		verificationOutcomes = append(verificationOutcomes, &SignatureVerificationOutcome{VerificationLevel: verificationLevel})
		return verificationOutcomes, nil
	}

	// make sure the reference exists in the registry
	artifactDigest, err := getArtifactDigestFromUri(artifactUri)
	if err != nil {
		return nil, ErrorSignatureRetrievalFailed{msg: err.Error()}
	}

	artifactDescriptor, err := v.Repository.Resolve(ctx, artifactDigest)
	if err != nil {
		return nil, ErrorSignatureRetrievalFailed{msg: err.Error()}
	}

	// get signature manifests
	sigManifests, err := v.Repository.ListSignatureManifests(ctx, artifactDescriptor.Digest)
	if err != nil {
		return nil, ErrorSignatureRetrievalFailed{msg: fmt.Sprintf("unable to retrieve digital signature(s) associated with %q from the registry, error : %s", artifactUri, err.Error())}
	}
	if len(sigManifests) < 1 {
		return nil, ErrorSignatureRetrievalFailed{msg: fmt.Sprintf("no signatures are associated with %q, make sure the image was signed successfully", artifactUri)}
	}

	// process signatures
	for _, sigManifest := range sigManifests {
		// get signature envelope
		sigBlob, err := v.Repository.GetBlob(ctx, sigManifest.Blob.Digest)
		if err != nil {
			return verificationOutcomes, ErrorSignatureRetrievalFailed{msg: fmt.Sprintf("unable to retrieve digital signature with digest %q associated with %q from the registry, error : %s", sigManifest.Blob.Digest, artifactUri, err.Error())}
		}
		outcome := &SignatureVerificationOutcome{
			VerificationResults: []*VerificationResult{},
			VerificationLevel:   verificationLevel,
		}
		err = v.processSignature(ctx, sigBlob, sigManifest, trustPolicy, outcome)
		if err != nil {
			outcome.Error = err
		}
		verificationOutcomes = append(verificationOutcomes, outcome)
	}

	// check whether verification was successful or not
	for _, outcome := range verificationOutcomes {

		// all validations must pass
		if outcome.Error != nil {
			continue
		}

		// artifact digest must match the digest from the signature payload
		payload := &notation.Payload{}
		err := json.Unmarshal(outcome.SignerInfo.Payload, payload)
		if err != nil || !artifactDescriptor.Equal(payload.TargetArtifact) {
			outcome.Error = fmt.Errorf("given digest %q does not match the digest %q present in the digital signature", artifactDigest, payload.TargetArtifact.Digest.String())
			continue
		}
		outcome.SignedAnnotations = payload.TargetArtifact.Annotations

		// signature verification succeeds if there is at least one good signature
		return verificationOutcomes, nil
	}

	return verificationOutcomes, ErrorVerificationFailed{}
}

func (v *Verifier) processSignature(ctx context.Context, sigBlob []byte, sigManifest registry.SignatureManifest, trustPolicy *TrustPolicy, outcome *SignatureVerificationOutcome) error {

	// verify integrity first. notation will always verify integrity no matter what the signing scheme is
	signerInfo, integrityResult := v.verifyIntegrity(sigBlob, sigManifest, outcome)
	outcome.SignerInfo = signerInfo
	outcome.VerificationResults = append(outcome.VerificationResults, integrityResult)
	if integrityResult.Error != nil {
		return integrityResult.Error
	}

	// check if we need to verify using a plugin
	var pluginCapabilities []plugin.Capability
	verificationPluginName := outcome.SignerInfo.SignedAttributes.VerificationPlugin
	if verificationPluginName != "" {
		installedPlugin, err := v.PluginManager.Get(ctx, verificationPluginName)
		if err != nil {
			return ErrorVerificationInconclusive{msg: fmt.Sprintf("error while loading the verification plugin %q: %s", verificationPluginName, err)}
		}

		// TODO verify the plugin version is equal to or greater than `outcome.SignerInfo.SignedAttributes.VerificationPluginMinVersion`

		// filter the verification capabilities supported by the installed plugin
		for _, capability := range installedPlugin.Capabilities {
			if capability.IsVerificationCapability() {
				pluginCapabilities = append(pluginCapabilities, capability)
			}
		}

		if len(pluginCapabilities) == 0 {
			return ErrorVerificationInconclusive{msg: fmt.Sprintf("digital signature requires plugin %q with signature verification capabilities installed", verificationPluginName)}
		}
	}

	// verify x509 trust store based authenticity
	authenticityResult := v.verifyAuthenticity(TrustStorePrefixCA, trustPolicy, outcome)
	outcome.VerificationResults = append(outcome.VerificationResults, authenticityResult)
	if isCriticalFailure(authenticityResult) {
		return authenticityResult.Error
	}

	// verify x509 trusted identity based authenticity (if notation needs to perform this verification rather than a plugin)
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
	// check if we need to bypass the revocation check, since revocation can be skipped using a trust policy or a plugin may perform the check
	if outcome.VerificationLevel.VerificationMap[Revocation] != Skipped && !plugin.CapabilityRevocationCheckVerifier.In(pluginCapabilities) {
		// TODO perform X509 revocation check (not in RC1)
	}

	// perform extended verification using verification plugin if present
	if len(pluginCapabilities) != 0 {
		var capabilitiesToVerify []plugin.VerificationCapability
		for _, pc := range pluginCapabilities {
			// skip the revocation capability if the trust policy is configured to skip it
			if outcome.VerificationLevel.VerificationMap[Revocation] == Skipped && pc == plugin.CapabilityRevocationCheckVerifier {
				continue
			}
			capabilitiesToVerify = append(capabilitiesToVerify, plugin.VerificationCapability(pc))
		}

		response, err := v.invokePlugin(ctx, trustPolicy, capabilitiesToVerify, outcome)
		if err != nil {
			return err
		}
		return v.processPluginResponse(capabilitiesToVerify, response, outcome)
	}

	return nil
}

func (v *Verifier) processPluginResponse(capabilitiesToVerify []plugin.VerificationCapability, response *plugin.VerifySignatureResponse, outcome *SignatureVerificationOutcome) error {
	verificationPluginName := outcome.SignerInfo.SignedAttributes.VerificationPlugin
	for _, capability := range capabilitiesToVerify {
		pluginResult := response.VerificationResults[capability]
		if reflect.DeepEqual(pluginResult, plugin.VerificationResult{}) {
			// verification result it empty for this capability
			return ErrorVerificationInconclusive{msg: fmt.Sprintf("verification plugin %q failed to verify %q", verificationPluginName, capability)}
		}
		if capability == plugin.VerificationCapabilityTrustedIdentity {
			// find the Authenticity VerificationResult that we already created during x509 trust store verification
			var authenticityResult *VerificationResult
			for _, r := range outcome.VerificationResults {
				if r.Type == Authenticity {
					authenticityResult = r
					break
				}
			}
			if !pluginResult.Success {
				authenticityResult.Error = fmt.Errorf("trusted identify verification by plugin %q failed with reason %q", verificationPluginName, pluginResult.Reason)
			}
			if isCriticalFailure(authenticityResult) {
				return authenticityResult.Error
			}
		} else if capability == plugin.VerificationCapabilityRevocationCheck {
			var revocationResult *VerificationResult
			if !pluginResult.Success {
				revocationResult = &VerificationResult{
					Success: false,
					Error:   fmt.Errorf("digital signature has expired on %q", outcome.SignerInfo.SignedAttributes.Expiry.Format(time.RFC1123Z)),
					Type:    Expiry,
					Action:  outcome.VerificationLevel.VerificationMap[Expiry],
				}
			} else {
				revocationResult = &VerificationResult{
					Success: true,
					Type:    Expiry,
					Action:  outcome.VerificationLevel.VerificationMap[Expiry],
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
