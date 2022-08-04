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
	signerInfo, result := v.verifyIntegrity(sigBlob, sigManifest, outcome)
	outcome.SignerInfo = signerInfo
	outcome.VerificationResults = append(outcome.VerificationResults, result)
	if result.Error != nil {
		return result.Error
	}

	// verify x509 and trust identity based authenticity
	result = v.verifyAuthenticity(TrustStorePrefixCA, trustPolicy, outcome)
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

	// Verify timestamping signature if present - Not in RC1
	// Verify revocation - Not in RC1
	// no error
	return nil
}
