package verification

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/plugin"
	"github.com/notaryproject/notation-go/plugin/manager"
	"github.com/notaryproject/notation-go/registry"
)

type Verifier struct {
	PolicyDocument *PolicyDocument
	Repository     registry.Repository
	PluginManager  pluginManager
}

// pluginManager is for mocking in unit tests
type pluginManager interface {
	Get(ctx context.Context, name string) (*manager.Plugin, error)
	Runner(name string) (plugin.Runner, error)
}

func NewVerifier(repository registry.Repository) (*Verifier, error) {
	// load trust policy
	policyDocument, err := loadPolicyDocument("") // TODO get the policy path from Dir Structure functionality
	if err != nil {
		return nil, err
	}
	if err = policyDocument.ValidatePolicyDocument(); err != nil {
		return nil, err
	}

	// load plugins
	pluginManager := manager.New("") // TODO get the plugins base path from Dir Structure functionality

	return &Verifier{
		PolicyDocument: policyDocument,
		Repository:     repository,
		PluginManager:  pluginManager,
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

	verificationLevel, _ := FindVerificationLevel(trustPolicy.SignatureVerification)

	if verificationLevel.Name == "skip" {
		verificationOutcomes = append(verificationOutcomes, &SignatureVerificationOutcome{VerificationLevel: verificationLevel})
		return verificationOutcomes, nil
	}

	// make sure the reference exists in the registry
	artifactDigest, err := getArtifactDigestFromUri(artifactUri)
	artifactDescriptor, err := v.Repository.Resolve(ctx, artifactDigest)
	if err != nil {
		return nil, ErrorSignatureRetrievalFailed{msg: err.Error()}
	}

	// get signature manifests
	sigManifests, err := v.Repository.ListSignatureManifests(ctx, artifactDescriptor.Digest)
	if err != nil {
		return nil, ErrorSignatureRetrievalFailed{msg: fmt.Sprintf("unable to retrieve digital signature/s associated with %q from the registry, error : %s", artifactUri, err.Error())}
	}
	if len(sigManifests) < 1 {
		return nil, ErrorSignatureRetrievalFailed{msg: fmt.Sprintf("no signatures are associated with %q, make sure the image was signed successfully", artifactUri)}
	}

	// process signatures
	for _, sigManifest := range sigManifests {
		// get signature envelope
		sigBlob, err := v.Repository.Get(ctx, sigManifest.Blob.Digest)
		if err != nil {
			return verificationOutcomes, ErrorSignatureRetrievalFailed{msg: fmt.Sprintf("unable to retrieve digital signature/s associated with %q from the registry, error : %s", artifactUri, err.Error())}
		}
		outcome := &SignatureVerificationOutcome{
			VerificationResults: []*VerificationResult{},
			VerificationLevel:   verificationLevel,
		}
		err = v.processSignature(sigBlob, sigManifest, trustPolicy, outcome)
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
		if err != nil || artifactDigest != payload.TargetArtifact.Digest.String() {
			outcome.Error = fmt.Errorf("given digest %q does not match the digest %q present in the digital signature", artifactDigest, payload.TargetArtifact.Digest.String())
			continue
		}
		outcome.SignedAnnotations = payload.TargetArtifact.Annotations

		// signature verification succeeds if there is at least one good signature
		return verificationOutcomes, nil
	}

	return verificationOutcomes, ErrorVerificationFailed{}
}

func (v *Verifier) processSignature(sigBlob []byte, sigManifest registry.SignatureManifest, trustPolicy *TrustPolicy, outcome *SignatureVerificationOutcome) error {
	// verify integrity first. notation will always verify integrity no matter what the signing scheme is
	signerInfo, result := v.verifyIntegrity(sigBlob, sigManifest, outcome)
	outcome.SignerInfo = signerInfo
	outcome.VerificationResults = append(outcome.VerificationResults, result)
	if isCriticalFailure(result) {
		return result.Error
	}

	// perform remaining validations based on the signing scheme
	if err := v.defaultVerification(trustPolicy, outcome); err != nil {
		return err
	}

	// no error
	return nil
}

// defaultVerification performs verification for the default singing scheme `notary.default.x509`
func (v *Verifier) defaultVerification(trustPolicy *TrustPolicy, outcome *SignatureVerificationOutcome) error {
	trustStorePrefix := "ca"

	// verify x509 and trust identity based authenticity
	result := v.verifyAuthenticity(trustStorePrefix, trustPolicy, outcome)
	outcome.VerificationResults = append(outcome.VerificationResults, result)
	if isCriticalFailure(result) {
		return result.Error
	}

	// verify expiry
	result = v.verifyExpiry(outcome)
	outcome.VerificationResults = append(outcome.VerificationResults, result)
	if isCriticalFailure(result) {
		return result.Error
	}

	// TODO verify timestamping signature if present - NOT in RC1
	// TODO verify certificate revocation - NOT in RC1
	return nil
}
