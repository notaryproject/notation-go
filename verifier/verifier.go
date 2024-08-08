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

// Package verifier provides an implementation of notation.Verifier interface
package verifier

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"time"

	"golang.org/x/mod/semver"
	"oras.land/oras-go/v2/content"

	"github.com/notaryproject/notation-core-go/revocation"
	"github.com/notaryproject/notation-core-go/revocation/purpose"
	revocationresult "github.com/notaryproject/notation-core-go/revocation/result"
	"github.com/notaryproject/notation-core-go/signature"
	nx509 "github.com/notaryproject/notation-core-go/x509"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/internal/envelope"
	"github.com/notaryproject/notation-go/internal/pkix"
	notationsemver "github.com/notaryproject/notation-go/internal/semver"
	"github.com/notaryproject/notation-go/internal/slices"
	trustpolicyInternal "github.com/notaryproject/notation-go/internal/trustpolicy"
	"github.com/notaryproject/notation-go/log"
	"github.com/notaryproject/notation-go/plugin"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	pluginframework "github.com/notaryproject/notation-plugin-framework-go/plugin"
	"github.com/notaryproject/tspclient-go"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

var algorithms = map[crypto.Hash]digest.Algorithm{
	crypto.SHA256: digest.SHA256,
	crypto.SHA384: digest.SHA384,
	crypto.SHA512: digest.SHA512,
}

// verifier implements notation.Verifier, notation.BlobVerifier and notation.verifySkipper
type verifier struct {
	ociTrustPolicyDoc               *trustpolicy.OCIDocument
	blobTrustPolicyDoc              *trustpolicy.BlobDocument
	trustStore                      truststore.X509TrustStore
	pluginManager                   plugin.Manager
	revocationClient                revocation.Revocation
	revocationCodeSigningValidator  revocation.Validator
	revocationTimestampingValidator revocation.Validator
}

// VerifierOptions specifies additional parameters that can be set when using
// the NewVerifierWithOptions constructor
type VerifierOptions struct {
	// RevocationClient is an implementation of revocation.Revocation to use for
	// verifying revocation of code signing certificate chain
	//
	// Deprecated: RevocationClient exists for backwards compatibility and
	// should not be used. To perform code signing certificate chain revocation
	// check, use [RevocationCodeSigningValidator].
	RevocationClient revocation.Revocation

	// RevocationCodeSigningValidator is used for verifying revocation of
	// code signing certificate chain with context.
	RevocationCodeSigningValidator revocation.Validator

	// RevocationTimestampingValidator is used for verifying revocation of
	// timestamping certificate chain with context.
	RevocationTimestampingValidator revocation.Validator
}

// NewOCIVerifierFromConfig returns a OCI verifier based on local file system
func NewOCIVerifierFromConfig() (*verifier, error) {
	// load trust policy
	policyDocument, err := trustpolicy.LoadOCIDocument()
	if err != nil {
		return nil, err
	}
	// load trust store
	x509TrustStore := truststore.NewX509TrustStore(dir.ConfigFS())

	return NewVerifier(policyDocument, nil, x509TrustStore, plugin.NewCLIManager(dir.PluginFS()))
}

// NewBlobVerifierFromConfig returns a Blob verifier based on local file system
func NewBlobVerifierFromConfig() (*verifier, error) {
	// load trust policy
	policyDocument, err := trustpolicy.LoadBlobDocument()
	if err != nil {
		return nil, err
	}
	// load trust store
	x509TrustStore := truststore.NewX509TrustStore(dir.ConfigFS())

	return NewVerifier(nil, policyDocument, x509TrustStore, plugin.NewCLIManager(dir.PluginFS()))
}

// NewWithOptions creates a new verifier given ociTrustPolicy, trustStore,
// pluginManager, and VerifierOptions.
//
// Deprecated: NewWithOptions function exists for historical compatibility and should not be used.
// To create verifier, use NewVerifierWithOptions function.
func NewWithOptions(ociTrustPolicy *trustpolicy.OCIDocument, trustStore truststore.X509TrustStore, pluginManager plugin.Manager, opts VerifierOptions) (notation.Verifier, error) {
	return NewVerifierWithOptions(ociTrustPolicy, nil, trustStore, pluginManager, opts)
}

// NewVerifier creates a new verifier given ociTrustPolicy, trustStore and pluginManager
func NewVerifier(ociTrustPolicy *trustpolicy.OCIDocument, blobTrustPolicy *trustpolicy.BlobDocument, trustStore truststore.X509TrustStore, pluginManager plugin.Manager) (*verifier, error) {
	return NewVerifierWithOptions(ociTrustPolicy, blobTrustPolicy, trustStore, pluginManager, VerifierOptions{})
}

// NewVerifierWithOptions creates a new verifier given ociTrustPolicy, blobTrustPolicy,
// trustStore, pluginManager, and verifierOptions
func NewVerifierWithOptions(ociTrustPolicy *trustpolicy.OCIDocument, blobTrustPolicy *trustpolicy.BlobDocument, trustStore truststore.X509TrustStore, pluginManager plugin.Manager, verifierOptions VerifierOptions) (*verifier, error) {
	if trustStore == nil {
		return nil, errors.New("trustStore cannot be nil")
	}
	if ociTrustPolicy == nil && blobTrustPolicy == nil {
		return nil, errors.New("ociTrustPolicy and blobTrustPolicy both cannot be nil")
	}
	if ociTrustPolicy != nil {
		if err := ociTrustPolicy.Validate(); err != nil {
			return nil, err
		}
	}
	if blobTrustPolicy != nil {
		if err := blobTrustPolicy.Validate(); err != nil {
			return nil, err
		}
	}
	v := &verifier{
		ociTrustPolicyDoc:  ociTrustPolicy,
		blobTrustPolicyDoc: blobTrustPolicy,
		trustStore:         trustStore,
		pluginManager:      pluginManager,
	}

	if err := v.setRevocation(verifierOptions); err != nil {
		return nil, err
	}
	return v, nil
}

// NewFromConfig returns a OCI verifier based on local file system.
//
// Deprecated: NewFromConfig function exists for historical compatibility and should not be used.
// To create an OCI verifier, use NewOCIVerifierFromConfig function.
func NewFromConfig() (notation.Verifier, error) {
	return NewOCIVerifierFromConfig()
}

// New creates a new verifier given ociTrustPolicy, trustStore and pluginManager.
//
// Deprecated: New function exists for historical compatibility and should not be used.
// To create verifier, use NewVerifier function.
func New(ociTrustPolicy *trustpolicy.OCIDocument, trustStore truststore.X509TrustStore, pluginManager plugin.Manager) (notation.Verifier, error) {
	return NewVerifier(ociTrustPolicy, nil, trustStore, pluginManager)
}

// setRevocation sets revocation validators of v
func (v *verifier) setRevocation(verifierOptions VerifierOptions) error {
	// timestamping validator
	revocationTimestampingValidator := verifierOptions.RevocationTimestampingValidator
	var err error
	if revocationTimestampingValidator == nil {
		revocationTimestampingValidator, err = revocation.NewWithOptions(revocation.Options{
			OCSPHTTPClient:   &http.Client{Timeout: 2 * time.Second},
			CertChainPurpose: purpose.Timestamping,
		})
		if err != nil {
			return err
		}
	}
	v.revocationTimestampingValidator = revocationTimestampingValidator

	// code signing validator
	revocationCodeSigningValidator := verifierOptions.RevocationCodeSigningValidator
	if revocationCodeSigningValidator != nil {
		v.revocationCodeSigningValidator = revocationCodeSigningValidator
		return nil
	}
	revocationClient := verifierOptions.RevocationClient
	if revocationClient != nil {
		v.revocationClient = revocationClient
		return nil
	}

	// both RevocationCodeSigningValidator and RevocationClient are nil
	revocationCodeSigningValidator, err = revocation.NewWithOptions(revocation.Options{
		OCSPHTTPClient:   &http.Client{Timeout: 2 * time.Second},
		CertChainPurpose: purpose.CodeSigning,
	})
	if err != nil {
		return err
	}
	v.revocationCodeSigningValidator = revocationCodeSigningValidator
	return nil
}

// SkipVerify validates whether the verification level is skip.
func (v *verifier) SkipVerify(ctx context.Context, opts notation.VerifierVerifyOptions) (bool, *trustpolicy.VerificationLevel, error) {
	logger := log.GetLogger(ctx)

	logger.Debugf("Check verification level against artifact %v", opts.ArtifactReference)
	trustPolicy, err := v.ociTrustPolicyDoc.GetApplicableTrustPolicy(opts.ArtifactReference)
	if err != nil {
		return false, nil, notation.ErrorNoApplicableTrustPolicy{Msg: err.Error()}
	}
	logger.Infof("Trust policy configuration: %+v", trustPolicy)

	// ignore the error since we already validated the policy document
	verificationLevel, _ := trustPolicy.SignatureVerification.GetVerificationLevel()
	// verificationLevel is skip
	if reflect.DeepEqual(verificationLevel, trustpolicy.LevelSkip) {
		logger.Debug("Skipping signature verification")
		return true, trustpolicy.LevelSkip, nil
	}

	return false, verificationLevel, nil
}

// VerifyBlob verifies the signature of given blob , and returns the outcome upon
// successful verification.
func (v *verifier) VerifyBlob(ctx context.Context, descGenFunc notation.BlobDescriptorGenerator, signature []byte, opts notation.BlobVerifierVerifyOptions) (*notation.VerificationOutcome, error) {
	logger := log.GetLogger(ctx)
	logger.Debugf("Verify signature of media type %v", opts.SignatureMediaType)
	if v.blobTrustPolicyDoc == nil {
		return nil, errors.New("blobTrustPolicyDoc is nil")
	}

	var trustPolicy *trustpolicy.BlobTrustPolicy
	var err error
	if opts.TrustPolicyName == "" {
		trustPolicy, err = v.blobTrustPolicyDoc.GetGlobalTrustPolicy()
	} else {
		trustPolicy, err = v.blobTrustPolicyDoc.GetApplicableTrustPolicy(opts.TrustPolicyName)
	}
	if err != nil {
		return nil, notation.ErrorNoApplicableTrustPolicy{Msg: err.Error()}
	}
	logger.Infof("Trust policy configuration: %+v", trustPolicy)

	// ignore the error since we already validated the policy document
	verificationLevel, _ := trustPolicy.SignatureVerification.GetVerificationLevel()
	outcome := &notation.VerificationOutcome{
		RawSignature:      signature,
		VerificationLevel: verificationLevel,
	}
	// verificationLevel is skip
	if reflect.DeepEqual(verificationLevel, trustpolicy.LevelSkip) {
		logger.Debug("Skipping signature verification")
		return outcome, nil
	}
	err = v.processSignature(ctx, signature, opts.SignatureMediaType, trustPolicy.Name, trustPolicy.TrustedIdentities, trustPolicy.TrustStores, trustPolicy.SignatureVerification, opts.PluginConfig, outcome)
	if err != nil {
		outcome.Error = err
		return outcome, err
	}

	payload := &envelope.Payload{}
	err = json.Unmarshal(outcome.EnvelopeContent.Payload.Content, payload)
	if err != nil {
		logger.Error("Failed to unmarshal the payload content in the signature blob to envelope.Payload")
		outcome.Error = err
		return outcome, err
	}

	cryptoHash := outcome.EnvelopeContent.SignerInfo.SignatureAlgorithm.Hash()
	digestAlgo, ok := algorithms[cryptoHash]
	if !ok {
		logger.Error("Unsupported hashing algorithm: %v", cryptoHash)
		err := fmt.Errorf("unsupported hashing algorithm: %v", cryptoHash)
		outcome.Error = err
		return outcome, err
	}

	desc, err := descGenFunc(digestAlgo)
	if err != nil {
		errMsg := fmt.Sprintf("failed to generate descriptor for given artifact. Error: %s", err)
		logger.Error(errMsg)
		descErr := errors.New(errMsg)
		outcome.Error = descErr
		return outcome, descErr
	}

	if desc.Digest != payload.TargetArtifact.Digest || desc.Size != payload.TargetArtifact.Size ||
		(desc.MediaType != "" && desc.MediaType != payload.TargetArtifact.MediaType) {
		logger.Infof("payload present in the signature: %+v", payload.TargetArtifact)
		logger.Infof("payload derived from the blob: %+v", desc)
		outcome.Error = errors.New("integrity check failed. signature does not match the given blob")
	}

	if len(opts.UserMetadata) > 0 {
		err := verifyUserMetadata(logger, payload, opts.UserMetadata)
		if err != nil {
			outcome.Error = err
		}
	}

	return outcome, outcome.Error
}

// Verify verifies the signature associated the target OCI
// artifact with manifest descriptor `desc`, and returns the outcome upon
// successful verification.
// If nil signature is present and the verification level is not 'skip',
// an error will be returned.
func (v *verifier) Verify(ctx context.Context, desc ocispec.Descriptor, signature []byte, opts notation.VerifierVerifyOptions) (*notation.VerificationOutcome, error) {
	artifactRef := opts.ArtifactReference
	envelopeMediaType := opts.SignatureMediaType
	pluginConfig := opts.PluginConfig
	logger := log.GetLogger(ctx)

	logger.Debugf("Verify signature against artifact %v referenced as %s in signature media type %v", desc.Digest, artifactRef, envelopeMediaType)
	if v.ociTrustPolicyDoc == nil {
		return nil, errors.New("ociTrustPolicyDoc is nil")
	}

	trustPolicy, err := v.ociTrustPolicyDoc.GetApplicableTrustPolicy(artifactRef)
	if err != nil {
		return nil, notation.ErrorNoApplicableTrustPolicy{Msg: err.Error()}
	}

	logger.Infof("Trust policy configuration: %+v", trustPolicy)
	// ignore the error since we already validated the policy document
	verificationLevel, _ := trustPolicy.SignatureVerification.GetVerificationLevel()

	outcome := &notation.VerificationOutcome{
		RawSignature:      signature,
		VerificationLevel: verificationLevel,
	}
	// verificationLevel is skip
	if reflect.DeepEqual(verificationLevel, trustpolicy.LevelSkip) {
		logger.Debug("Skipping signature verification")
		return outcome, nil
	}
	err = v.processSignature(ctx, signature, envelopeMediaType, trustPolicy.Name, trustPolicy.TrustedIdentities, trustPolicy.TrustStores, trustPolicy.SignatureVerification, pluginConfig, outcome)

	if err != nil {
		outcome.Error = err
		return outcome, err
	}

	payload := &envelope.Payload{}
	err = json.Unmarshal(outcome.EnvelopeContent.Payload.Content, payload)
	if err != nil {
		logger.Error("Failed to unmarshal the payload content in the signature blob to envelope.Payload")
		outcome.Error = err
		return outcome, err
	}

	if !content.Equal(payload.TargetArtifact, desc) {
		logger.Infof("Target artifact in signature payload: %+v", payload.TargetArtifact)
		logger.Infof("Target artifact that want to be verified: %+v", desc)
		outcome.Error = errors.New("content descriptor mismatch")
	}

	if len(opts.UserMetadata) > 0 {
		err := verifyUserMetadata(logger, payload, opts.UserMetadata)
		if err != nil {
			outcome.Error = err
		}
	}

	return outcome, outcome.Error
}

func (v *verifier) processSignature(ctx context.Context, sigBlob []byte, envelopeMediaType, policyName string, trustedIdentities, trustStores []string, signatureVerification trustpolicy.SignatureVerification, pluginConfig map[string]string, outcome *notation.VerificationOutcome) error {
	logger := log.GetLogger(ctx)

	// verify integrity first. notation will always verify integrity no matter
	// what the signing scheme is
	envContent, integrityResult := verifyIntegrity(sigBlob, envelopeMediaType, outcome)
	outcome.EnvelopeContent = envContent
	outcome.VerificationResults = append(outcome.VerificationResults, integrityResult)
	if integrityResult.Error != nil {
		logVerificationResult(logger, integrityResult)
		return integrityResult.Error
	}

	// check if we need to verify using a plugin
	var pluginCapabilities []pluginframework.Capability
	verificationPluginName, err := getVerificationPlugin(&outcome.EnvelopeContent.SignerInfo)
	// use plugin, but getPluginName returns an error
	if err != nil && err != errExtendedAttributeNotExist {
		return err
	}

	var installedPlugin pluginframework.VerifyPlugin
	if verificationPluginName != "" {
		logger.Debugf("Finding verification plugin %s", verificationPluginName)
		verificationPluginMinVersion, err := getVerificationPluginMinVersion(&outcome.EnvelopeContent.SignerInfo)
		if err != nil && err != errExtendedAttributeNotExist {
			return notation.ErrorVerificationInconclusive{Msg: fmt.Sprintf("error while getting plugin minimum version, error: %s", err)}
		}

		if v.pluginManager == nil {
			return notation.ErrorVerificationInconclusive{Msg: "plugin unsupported due to nil verifier.pluginManager"}
		}
		installedPlugin, err = v.pluginManager.Get(ctx, verificationPluginName)
		if err != nil {
			return notation.ErrorVerificationInconclusive{Msg: fmt.Sprintf("error while locating the verification plugin %q, make sure the plugin is installed successfully before verifying the signature. error: %s", verificationPluginName, err)}
		}

		// filter the "verification" capabilities supported by the installed
		// plugin
		metadata, err := installedPlugin.GetMetadata(ctx, &pluginframework.GetMetadataRequest{PluginConfig: pluginConfig})
		if err != nil {
			return err
		}

		pluginVersion := metadata.Version

		//checking if the plugin version is in valid semver format
		if !notationsemver.IsValid(pluginVersion) {
			return notation.ErrorVerificationInconclusive{Msg: fmt.Sprintf("plugin %s has pluginVersion %s which is not in valid semver format", verificationPluginName, pluginVersion)}
		}

		if !isRequiredVerificationPluginVer(pluginVersion, verificationPluginMinVersion) {
			return notation.ErrorVerificationInconclusive{Msg: fmt.Sprintf("found plugin %s with version %s but signature verification needs plugin version greater than or equal to %s", verificationPluginName, pluginVersion, verificationPluginMinVersion)}
		}

		for _, capability := range metadata.Capabilities {
			if capability == pluginframework.CapabilityRevocationCheckVerifier || capability == pluginframework.CapabilityTrustedIdentityVerifier {
				pluginCapabilities = append(pluginCapabilities, capability)
			}
		}

		if len(pluginCapabilities) == 0 {
			return notation.ErrorVerificationInconclusive{Msg: fmt.Sprintf("digital signature requires plugin %q with signature verification capabilities (%q and/or %q) installed", verificationPluginName, pluginframework.CapabilityTrustedIdentityVerifier, pluginframework.CapabilityRevocationCheckVerifier)}
		}
	}

	// verify x509 trust store based authenticity
	logger.Debug("Validating cert chain")
	trustCerts, err := loadX509TrustStores(ctx, outcome.EnvelopeContent.SignerInfo.SignedAttributes.SigningScheme, policyName, trustStores, v.trustStore)
	var authenticityResult *notation.ValidationResult
	if err != nil {
		authenticityResult = &notation.ValidationResult{
			Error:  err,
			Type:   trustpolicy.TypeAuthenticity,
			Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeAuthenticity],
		}
	} else {
		// verify authenticity
		authenticityResult = verifyAuthenticity(trustCerts, outcome)
	}
	outcome.VerificationResults = append(outcome.VerificationResults, authenticityResult)
	logVerificationResult(logger, authenticityResult)
	if isCriticalFailure(authenticityResult) {
		return authenticityResult.Error
	}

	// verify x509 trusted identity based authenticity (only if notation needs
	// to perform this verification rather than a plugin)
	if !slices.Contains(pluginCapabilities, pluginframework.CapabilityTrustedIdentityVerifier) {
		logger.Debug("Validating trust identity")
		err = verifyX509TrustedIdentities(policyName, trustedIdentities, outcome.EnvelopeContent.SignerInfo.CertificateChain)
		if err != nil {
			authenticityResult.Error = err
			logVerificationResult(logger, authenticityResult)
		}
		if isCriticalFailure(authenticityResult) {
			return authenticityResult.Error
		}
	}

	// verify expiry
	logger.Debug("Validating expiry")
	expiryResult := verifyExpiry(outcome)
	outcome.VerificationResults = append(outcome.VerificationResults, expiryResult)
	logVerificationResult(logger, expiryResult)
	if isCriticalFailure(expiryResult) {
		return expiryResult.Error
	}

	// verify authentic timestamp
	logger.Debug("Validating authentic timestamp")
	authenticTimestampResult := verifyAuthenticTimestamp(ctx, policyName, trustStores, signatureVerification, v.trustStore, v.revocationTimestampingValidator, outcome)
	outcome.VerificationResults = append(outcome.VerificationResults, authenticTimestampResult)
	logVerificationResult(logger, authenticTimestampResult)
	if isCriticalFailure(authenticTimestampResult) {
		return authenticTimestampResult.Error
	}

	// verify revocation
	// check if we need to bypass the revocation check, since revocation can be
	// skipped using a trust policy or a plugin may override the check
	if outcome.VerificationLevel.Enforcement[trustpolicy.TypeRevocation] != trustpolicy.ActionSkip &&
		!slices.Contains(pluginCapabilities, pluginframework.CapabilityRevocationCheckVerifier) {

		logger.Debug("Validating revocation")
		revocationResult := v.verifyRevocation(ctx, outcome)
		outcome.VerificationResults = append(outcome.VerificationResults, revocationResult)
		logVerificationResult(logger, revocationResult)
		if isCriticalFailure(revocationResult) {
			return revocationResult.Error
		}
	}

	// perform extended verification using verification plugin if present
	if installedPlugin != nil {
		var capabilitiesToVerify []pluginframework.Capability
		for _, pc := range pluginCapabilities {
			// skip the revocation capability if the trust policy is configured
			// to skip it
			if outcome.VerificationLevel.Enforcement[trustpolicy.TypeRevocation] == trustpolicy.ActionSkip && pc == pluginframework.CapabilityRevocationCheckVerifier {
				logger.Debugf("Skipping the %v validation", pc)
				continue
			}
			capabilitiesToVerify = append(capabilitiesToVerify, pc)
		}

		if len(capabilitiesToVerify) > 0 {
			logger.Debugf("Executing verification plugin %q with capabilities %v", verificationPluginName, capabilitiesToVerify)
			response, err := executePlugin(ctx, installedPlugin, capabilitiesToVerify, outcome.EnvelopeContent, trustedIdentities, pluginConfig)
			if err != nil {
				return fmt.Errorf("failed to verify with plugin %s: %w", verificationPluginName, err)
			}

			return processPluginResponse(capabilitiesToVerify, response, outcome)
		}
	}
	return nil
}

func (v *verifier) verifyRevocation(ctx context.Context, outcome *notation.VerificationOutcome) *notation.ValidationResult {
	logger := log.GetLogger(ctx)

	if v.revocationCodeSigningValidator == nil && v.revocationClient == nil {
		return &notation.ValidationResult{
			Type:   trustpolicy.TypeRevocation,
			Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeRevocation],
			Error:  fmt.Errorf("unable to check revocation status, code signing revocation validator cannot be nil"),
		}
	}

	var authenticSigningTime time.Time
	if outcome.EnvelopeContent.SignerInfo.SignedAttributes.SigningScheme == signature.SigningSchemeX509SigningAuthority {
		authenticSigningTime, _ = outcome.EnvelopeContent.SignerInfo.AuthenticSigningTime()
	}

	var certResults []*revocationresult.CertRevocationResult
	var err error
	if v.revocationCodeSigningValidator != nil {
		certResults, err = v.revocationCodeSigningValidator.ValidateContext(ctx, revocation.ValidateContextOptions{
			CertChain:            outcome.EnvelopeContent.SignerInfo.CertificateChain,
			AuthenticSigningTime: authenticSigningTime,
		})
	} else {
		certResults, err = v.revocationClient.Validate(outcome.EnvelopeContent.SignerInfo.CertificateChain, authenticSigningTime)
	}
	if err != nil {
		logger.Debug("Error while checking revocation status, err: %s", err.Error())
		return &notation.ValidationResult{
			Type:   trustpolicy.TypeRevocation,
			Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeRevocation],
			Error:  fmt.Errorf("unable to check revocation status, err: %s", err.Error()),
		}
	}

	result := &notation.ValidationResult{
		Type:   trustpolicy.TypeRevocation,
		Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeRevocation],
	}
	finalResult, problematicCertSubject := revocationFinalResult(certResults, outcome.EnvelopeContent.SignerInfo.CertificateChain, logger)
	switch finalResult {
	case revocationresult.ResultOK:
		logger.Debug("No verification impacting errors encountered while checking revocation, status is OK")
	case revocationresult.ResultRevoked:
		result.Error = fmt.Errorf("signing certificate with subject %q is revoked", problematicCertSubject)
	default:
		// revocationresult.ResultUnknown
		result.Error = fmt.Errorf("signing certificate with subject %q revocation status is unknown", problematicCertSubject)
	}

	return result
}

func processPluginResponse(capabilitiesToVerify []pluginframework.Capability, response *pluginframework.VerifySignatureResponse, outcome *notation.VerificationOutcome) error {
	verificationPluginName, err := getVerificationPlugin(&outcome.EnvelopeContent.SignerInfo)
	if err != nil {
		return err
	}

	// verify all extended critical attributes are processed by the plugin
	for _, attr := range getNonPluginExtendedCriticalAttributes(&outcome.EnvelopeContent.SignerInfo) {
		if !slices.ContainsAny(response.ProcessedAttributes, attr.Key) {
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
		case pluginframework.CapabilityTrustedIdentityVerifier:
			if !pluginResult.Success {
				// find the Authenticity VerificationResult that we already
				// created during x509 trust store verification
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
		case pluginframework.CapabilityRevocationCheckVerifier:
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

func verifyIntegrity(sigBlob []byte, envelopeMediaType string, outcome *notation.VerificationOutcome) (*signature.EnvelopeContent, *notation.ValidationResult) {
	// parse the signature
	sigEnv, err := signature.ParseEnvelope(envelopeMediaType, sigBlob)
	if err != nil {
		return nil, &notation.ValidationResult{
			Error:  fmt.Errorf("unable to parse the digital signature, error : %s", err),
			Type:   trustpolicy.TypeIntegrity,
			Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeIntegrity],
		}
	}

	// verify integrity
	envContent, err := sigEnv.Verify()
	if err != nil {
		switch err.(type) {
		case *signature.SignatureEnvelopeNotFoundError, *signature.InvalidSignatureError, *signature.SignatureIntegrityError:
			return nil, &notation.ValidationResult{
				Error:  err,
				Type:   trustpolicy.TypeIntegrity,
				Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeIntegrity],
			}
		default:
			// unexpected error
			return nil, &notation.ValidationResult{
				Error:  notation.ErrorVerificationInconclusive{Msg: err.Error()},
				Type:   trustpolicy.TypeIntegrity,
				Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeIntegrity],
			}
		}
	}

	if err := envelope.ValidatePayloadContentType(&envContent.Payload); err != nil {
		return nil, &notation.ValidationResult{
			Error:  err,
			Type:   trustpolicy.TypeIntegrity,
			Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeIntegrity],
		}
	}

	// integrity has been verified successfully
	return envContent, &notation.ValidationResult{
		Type:   trustpolicy.TypeIntegrity,
		Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeIntegrity],
	}
}

func verifyAuthenticity(trustCerts []*x509.Certificate, outcome *notation.VerificationOutcome) *notation.ValidationResult {
	if len(trustCerts) < 1 {
		return &notation.ValidationResult{
			Error:  notation.ErrorVerificationInconclusive{Msg: "no trusted certificates are found to verify authenticity"},
			Type:   trustpolicy.TypeAuthenticity,
			Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeAuthenticity],
		}
	}
	_, err := signature.VerifyAuthenticity(&outcome.EnvelopeContent.SignerInfo, trustCerts)
	if err != nil {
		switch err.(type) {
		case *signature.SignatureAuthenticityError:
			return &notation.ValidationResult{
				Error:  err,
				Type:   trustpolicy.TypeAuthenticity,
				Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeAuthenticity],
			}
		default:
			return &notation.ValidationResult{
				Error:  notation.ErrorVerificationInconclusive{Msg: "authenticity verification failed with error : " + err.Error()},
				Type:   trustpolicy.TypeAuthenticity,
				Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeAuthenticity],
			}
		}
	}

	return &notation.ValidationResult{
		Type:   trustpolicy.TypeAuthenticity,
		Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeAuthenticity],
	}
}

func verifyUserMetadata(logger log.Logger, payload *envelope.Payload, userMetadata map[string]string) error {
	logger.Debugf("Verifying that metadata %v is present in signature", userMetadata)
	logger.Debugf("Signature metadata: %v", payload.TargetArtifact.Annotations)

	for k, v := range userMetadata {
		if got, ok := payload.TargetArtifact.Annotations[k]; !ok || got != v {
			logger.Errorf("User required metadata %s=%s is not present in the signature", k, v)
			return notation.ErrorUserMetadataVerificationFailed{}
		}
	}

	return nil
}

func verifyExpiry(outcome *notation.VerificationOutcome) *notation.ValidationResult {
	if expiry := outcome.EnvelopeContent.SignerInfo.SignedAttributes.Expiry; !expiry.IsZero() && !time.Now().Before(expiry) {
		return &notation.ValidationResult{
			Error:  fmt.Errorf("digital signature has expired on %q", expiry.Format(time.RFC1123Z)),
			Type:   trustpolicy.TypeExpiry,
			Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeExpiry],
		}
	}

	return &notation.ValidationResult{
		Type:   trustpolicy.TypeExpiry,
		Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeExpiry],
	}
}

func verifyAuthenticTimestamp(ctx context.Context, policyName string, trustStores []string, signatureVerification trustpolicy.SignatureVerification, x509TrustStore truststore.X509TrustStore, r revocation.Validator, outcome *notation.VerificationOutcome) *notation.ValidationResult {
	logger := log.GetLogger(ctx)

	signerInfo := outcome.EnvelopeContent.SignerInfo
	// under signing scheme notary.x509
	if signerInfo.SignedAttributes.SigningScheme == signature.SigningSchemeX509 {
		logger.Debug("Under signing scheme notary.x509...")
		return &notation.ValidationResult{
			Error:  verifyTimestamp(ctx, policyName, trustStores, signatureVerification, x509TrustStore, r, outcome),
			Type:   trustpolicy.TypeAuthenticTimestamp,
			Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeAuthenticTimestamp],
		}
	}

	// under signing scheme notary.x509.signingAuthority
	logger.Debug("Under signing scheme notary.x509.signingAuthority...")
	authenticSigningTime := signerInfo.SignedAttributes.SigningTime
	for _, cert := range signerInfo.CertificateChain {
		if authenticSigningTime.Before(cert.NotBefore) || authenticSigningTime.After(cert.NotAfter) {
			return &notation.ValidationResult{
				Error:  fmt.Errorf("certificate %q was not valid when the digital signature was produced at %q", cert.Subject, authenticSigningTime.Format(time.RFC1123Z)),
				Type:   trustpolicy.TypeAuthenticTimestamp,
				Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeAuthenticTimestamp],
			}
		}
	}

	// success
	return &notation.ValidationResult{
		Type:   trustpolicy.TypeAuthenticTimestamp,
		Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeAuthenticTimestamp],
	}
}

// revocationFinalResult returns the final revocation result and problematic
// certificate subject if the final result is not ResultOK
func revocationFinalResult(certResults []*revocationresult.CertRevocationResult, certChain []*x509.Certificate, logger log.Logger) (revocationresult.Result, string) {
	finalResult := revocationresult.ResultUnknown
	numOKResults := 0
	var problematicCertSubject string
	revokedFound := false
	var revokedCertSubject string
	for i := len(certResults) - 1; i >= 0; i-- {
		if len(certResults[i].ServerResults) > 0 && certResults[i].ServerResults[0].Error != nil {
			logger.Debugf("Error for certificate #%d in chain with subject %v for server %q: %v", (i + 1), certChain[i].Subject.String(), certResults[i].ServerResults[0].Server, certResults[i].ServerResults[0].Error)
		}

		if certResults[i].Result == revocationresult.ResultOK || certResults[i].Result == revocationresult.ResultNonRevokable {
			numOKResults++
		} else {
			finalResult = certResults[i].Result
			problematicCertSubject = certChain[i].Subject.String()
			if certResults[i].Result == revocationresult.ResultRevoked {
				revokedFound = true
				revokedCertSubject = problematicCertSubject
			}
		}
	}
	if revokedFound {
		problematicCertSubject = revokedCertSubject
		finalResult = revocationresult.ResultRevoked
	}
	if numOKResults == len(certResults) {
		finalResult = revocationresult.ResultOK
	}
	return finalResult, problematicCertSubject
}

func executePlugin(ctx context.Context, installedPlugin pluginframework.VerifyPlugin, capabilitiesToVerify []pluginframework.Capability, envelopeContent *signature.EnvelopeContent, trustedIdentities []string, pluginConfig map[string]string) (*pluginframework.VerifySignatureResponse, error) {
	logger := log.GetLogger(ctx)
	// sanity check
	if installedPlugin == nil {
		return nil, errors.New("installedPlugin cannot be nil")
	}

	signerInfo, payloadInfo := &envelopeContent.SignerInfo, envelopeContent.Payload
	var attributesToProcess []string
	extendedAttributes := make(map[string]interface{})

	for _, attr := range getNonPluginExtendedCriticalAttributes(signerInfo) {
		extendedAttributes[attr.Key.(string)] = attr.Value
		attributesToProcess = append(attributesToProcess, attr.Key.(string))
	}
	logger.Debugf("Added plugin attributes to be processed %v", attributesToProcess)

	var certChain [][]byte
	for _, cert := range signerInfo.CertificateChain {
		certChain = append(certChain, cert.Raw)
	}
	var authenticSigningTime *time.Time
	if signerInfo.SignedAttributes.SigningScheme == signature.SigningSchemeX509SigningAuthority {
		authenticSigningTime = &signerInfo.SignedAttributes.SigningTime
		// TODO use authenticSigningTime from signerInfo
		// https://github.com/notaryproject/notation-core-go/issues/38
	}

	sig := pluginframework.Signature{
		CriticalAttributes: pluginframework.CriticalAttributes{
			ContentType:          payloadInfo.ContentType,
			SigningScheme:        string(signerInfo.SignedAttributes.SigningScheme),
			Expiry:               &signerInfo.SignedAttributes.Expiry,
			AuthenticSigningTime: authenticSigningTime,
			ExtendedAttributes:   extendedAttributes,
		},
		UnprocessedAttributes: attributesToProcess,
		CertificateChain:      certChain,
	}

	policy := pluginframework.TrustPolicy{
		TrustedIdentities:     trustedIdentities,
		SignatureVerification: capabilitiesToVerify,
	}

	req := &pluginframework.VerifySignatureRequest{
		ContractVersion: pluginframework.ContractVersion,
		Signature:       sig,
		TrustPolicy:     policy,
		PluginConfig:    pluginConfig,
	}
	return installedPlugin.VerifySignature(ctx, req)
}

func verifyX509TrustedIdentities(policyName string, trustedIdentities []string, certs []*x509.Certificate) error {
	if slices.Contains(trustedIdentities, trustpolicyInternal.Wildcard) {
		return nil
	}

	var trustedX509Identities []map[string]string
	for _, identity := range trustedIdentities {
		identityPrefix, identityValue, found := strings.Cut(identity, ":")
		if !found {
			return fmt.Errorf("trust policy statement %q has trusted identity %q missing separator", policyName, identity)
		}

		// notation natively supports x509.subject identities only
		if identityPrefix == trustpolicyInternal.X509Subject {
			// identityValue cannot be empty
			if identityValue == "" {
				return fmt.Errorf("trust policy statement %q has trusted identity %q without an identity value", policyName, identity)
			}
			parsedSubject, err := pkix.ParseDistinguishedName(identityValue)
			if err != nil {
				return err
			}
			trustedX509Identities = append(trustedX509Identities, parsedSubject)
		}
	}

	if len(trustedX509Identities) == 0 {
		return fmt.Errorf("no x509 trusted identities are configured in the trust policy %q", policyName)
	}

	leafCert := certs[0] // trusted identities only supported on the leaf cert

	// parse the certificate subject following rfc 4514 DN syntax
	leafCertDN, err := pkix.ParseDistinguishedName(leafCert.Subject.String())
	if err != nil {
		return fmt.Errorf("error while parsing the certificate subject from the digital signature. error : %q", err)
	}
	for _, trustedX509Identity := range trustedX509Identities {
		if pkix.IsSubsetDN(trustedX509Identity, leafCertDN) {
			return nil
		}
	}

	return fmt.Errorf("signing certificate from the digital signature does not match the X.509 trusted identities %q defined in the trust policy %q", trustedX509Identities, policyName)
}

func logVerificationResult(logger log.Logger, result *notation.ValidationResult) {
	if result.Error == nil {
		return
	}
	switch result.Action {
	case trustpolicy.ActionLog:
		logger.Warnf("%v validation failed with validation action set to \"logged\". Failure reason: %v", result.Type, result.Error)
	case trustpolicy.ActionEnforce:
		logger.Errorf("%v validation failed. Failure reason: %v", result.Type, result.Error)
	}
}

func isRequiredVerificationPluginVer(pluginVer string, minPluginVer string) bool {
	return semver.Compare("v"+pluginVer, "v"+minPluginVer) != -1
}

// verifyTimestamp provides core verification logic of authentic timestamp under
// signing scheme `notary.x509`.
func verifyTimestamp(ctx context.Context, policyName string, trustStores []string, signatureVerification trustpolicy.SignatureVerification, x509TrustStore truststore.X509TrustStore, r revocation.Validator, outcome *notation.VerificationOutcome) error {
	logger := log.GetLogger(ctx)

	signerInfo := outcome.EnvelopeContent.SignerInfo
	performTimestampVerification := true

	// check if tsa trust store is configured in trust policy
	tsaEnabled, err := isTSATrustStoreInPolicy(policyName, trustStores)
	if err != nil {
		return fmt.Errorf("failed to check tsa trust store configuration in turst policy with error: %w", err)
	}
	if !tsaEnabled {
		logger.Info("Timestamp verification disabled: no tsa trust store is configured in trust policy")
		performTimestampVerification = false
	}

	// check based on 'verifyTimestamp' field
	timeOfVerification := time.Now()
	if performTimestampVerification &&
		signatureVerification.VerifyTimestamp == trustpolicy.OptionAfterCertExpiry {
		// check if signing cert chain has expired
		var expired bool
		for _, cert := range signerInfo.CertificateChain {
			if timeOfVerification.After(cert.NotAfter) {
				expired = true
				break
			}
		}
		if !expired {
			logger.Infof("Timestamp verification disabled: verifyTimestamp is set to %q and signing cert chain unexpired", trustpolicy.OptionAfterCertExpiry)
			performTimestampVerification = false
		}
	}

	// timestamp verification disabled, signing cert chain MUST be valid
	// at time of verification
	if !performTimestampVerification {
		for _, cert := range signerInfo.CertificateChain {
			if timeOfVerification.Before(cert.NotBefore) {
				return fmt.Errorf("verification time is before certificate %q validity period, it will be valid from %q", cert.Subject, cert.NotBefore.Format(time.RFC1123Z))
			}
			if timeOfVerification.After(cert.NotAfter) {
				return fmt.Errorf("verification time is after certificate %q validity period, it was expired at %q", cert.Subject, cert.NotAfter.Format(time.RFC1123Z))
			}
		}

		// success
		return nil
	}

	// Performing timestamp verification
	logger.Info("Performing timestamp verification...")

	// 1. Timestamp countersignature MUST be present
	logger.Debug("Checking timestamp countersignature existence...")
	if len(signerInfo.UnsignedAttributes.TimestampSignature) == 0 {
		return errors.New("no timestamp countersignature was found in the signature envelope")
	}

	// 2. Verify the timestamp countersignature
	logger.Debug("Verifying the timestamp countersignature...")
	signedToken, err := tspclient.ParseSignedToken(signerInfo.UnsignedAttributes.TimestampSignature)
	if err != nil {
		return fmt.Errorf("failed to parse timestamp countersignature with error: %w", err)
	}
	info, err := signedToken.Info()
	if err != nil {
		return fmt.Errorf("failed to get the timestamp TSTInfo with error: %w", err)
	}
	timestamp, err := info.Validate(signerInfo.Signature)
	if err != nil {
		return fmt.Errorf("failed to get timestamp from timestamp countersignature with error: %w", err)
	}
	trustTSACerts, err := loadX509TSATrustStores(ctx, outcome.EnvelopeContent.SignerInfo.SignedAttributes.SigningScheme, policyName, trustStores, x509TrustStore)
	if err != nil {
		return fmt.Errorf("failed to load tsa trust store with error: %w", err)
	}
	if len(trustTSACerts) == 0 {
		return errors.New("no trusted TSA certificate found in trust store")
	}
	rootCertPool := x509.NewCertPool()
	for _, trustedCerts := range trustTSACerts {
		rootCertPool.AddCert(trustedCerts)
	}
	tsaCertChain, err := signedToken.Verify(ctx, x509.VerifyOptions{
		CurrentTime: timestamp.Value,
		Roots:       rootCertPool,
	})
	if err != nil {
		return fmt.Errorf("failed to verify the timestamp countersignature with error: %w", err)
	}

	// 3. Validate timestamping certificate chain
	logger.Debug("Validating timestamping certificate chain...")
	if err := nx509.ValidateTimestampingCertChain(tsaCertChain); err != nil {
		return fmt.Errorf("failed to validate the timestamping certificate chain with error: %w", err)
	}
	logger.Info("TSA identity is: ", tsaCertChain[0].Subject)

	// 4. Check the timestamp against the signing certificate chain
	logger.Debug("Checking the timestamp against the signing certificate chain...")
	logger.Debugf("Timestamp range: %s", timestamp.Format(time.RFC3339))
	for _, cert := range signerInfo.CertificateChain {
		if !timestamp.BoundedAfter(cert.NotBefore) {
			return fmt.Errorf("timestamp can be before certificate %q validity period, it will be valid from %q", cert.Subject, cert.NotBefore.Format(time.RFC1123Z))
		}
		if !timestamp.BoundedBefore(cert.NotAfter) {
			return fmt.Errorf("timestamp can be after certificate %q validity period, it was expired at %q", cert.Subject, cert.NotAfter.Format(time.RFC1123Z))
		}
	}

	// 5. Perform the timestamping certificate chain revocation check
	logger.Debug("Checking timestamping certificate chain revocation...")
	certResults, err := r.ValidateContext(ctx, revocation.ValidateContextOptions{
		CertChain: tsaCertChain,
	})
	if err != nil {
		return fmt.Errorf("failed to check timestamping certificate chain revocation with error: %w", err)
	}
	finalResult, problematicCertSubject := revocationFinalResult(certResults, tsaCertChain, logger)
	switch finalResult {
	case revocationresult.ResultOK:
		logger.Debug("No verification impacting errors encountered while checking timestamping certificate chain revocation, status is OK")
	case revocationresult.ResultRevoked:
		return fmt.Errorf("timestamping certificate with subject %q is revoked", problematicCertSubject)
	default:
		// revocationresult.ResultUnknown
		return fmt.Errorf("timestamping certificate with subject %q revocation status is unknown", problematicCertSubject)
	}

	// success
	return nil
}
