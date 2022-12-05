// Package Verifier provides an implementation of notation.Verifier interface
package verifier

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/internal/envelope"
	"github.com/notaryproject/notation-go/internal/pkix"
	"github.com/notaryproject/notation-go/internal/slices"
	trustpolicyInternal "github.com/notaryproject/notation-go/internal/trustpolicy"
	"github.com/notaryproject/notation-go/log"
	"github.com/notaryproject/notation-go/plugin"
	"github.com/notaryproject/notation-go/plugin/proto"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
)

// verifier implements notation.Verifier
type verifier struct {
	trustPolicyDoc *trustpolicy.Document
	trustStore     truststore.X509TrustStore
	pluginManager  plugin.Manager
}

// NewFromConfig returns a verifier based on local file system
func NewFromConfig() (notation.Verifier, error) {
	// load trust policy
	policyDocument, err := trustpolicy.LoadDocument()
	if err != nil {
		return nil, err
	}
	// load trust store
	x509TrustStore := truststore.NewX509TrustStore(dir.ConfigFS())

	return New(policyDocument, x509TrustStore, plugin.NewCLIManager(dir.PluginFS()))
}

// New creates a new verifier given trustPolicy, trustStore and pluginManager
func New(trustPolicy *trustpolicy.Document, trustStore truststore.X509TrustStore, pluginManager plugin.Manager) (notation.Verifier, error) {
	if trustPolicy == nil || trustStore == nil {
		return nil, errors.New("trustPolicy or trustStore cannot be nil")
	}
	if err := trustPolicy.Validate(); err != nil {
		return nil, err
	}
	return &verifier{
		trustPolicyDoc: trustPolicy,
		trustStore:     trustStore,
		pluginManager:  pluginManager,
	}, nil
}

// SkipVerify validates whether the verification level is skip.
func (v *verifier) SkipVerify(ctx context.Context, artifactRef string) (bool, *trustpolicy.VerificationLevel, error) {
	logger := log.GetLogger(ctx)

	logger.Debugf("Check verification level against artifact %v", artifactRef)
	trustPolicy, err := v.trustPolicyDoc.GetApplicableTrustPolicy(artifactRef)
	if err != nil {
		return false, nil, notation.ErrorNoApplicableTrustPolicy{Msg: err.Error()}
	}
	logger.Debugf("Trust policy configuration: %+v", trustPolicy)
	// ignore the error since we already validated the policy document
	verificationLevel, _ := trustPolicy.SignatureVerification.GetVerificationLevel()

	// verificationLevel is skip
	if reflect.DeepEqual(verificationLevel, trustpolicy.LevelSkip) {
		logger.Debug("Skipping signature verification")
		return true, verificationLevel, nil
	}
	return false, verificationLevel, nil
}

// Verify verifies the signature blob and returns the verified descriptor
// upon successful verification.
func (v *verifier) Verify(ctx context.Context, desc ocispec.Descriptor, signature []byte, opts notation.VerifyOptions) (*notation.VerificationOutcome, error) {
	artifactRef := opts.ArtifactReference
	envelopeMediaType := opts.SignatureMediaType
	pluginConfig := opts.PluginConfig
	logger := log.GetLogger(ctx)

	logger.Debugf("Verify signature against artifact %v referenced as %s in signature media type %v", desc.Digest, artifactRef, opts.SignatureMediaType)
	trustPolicy, err := v.trustPolicyDoc.GetApplicableTrustPolicy(artifactRef)
	if err != nil {
		return nil, notation.ErrorNoApplicableTrustPolicy{Msg: err.Error()}
	}
	logger.Debugf("Trust policy configuration: %+v", trustPolicy)
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
	err = v.processSignature(ctx, signature, envelopeMediaType, trustPolicy, pluginConfig, outcome)

	if err != nil {
		outcome.Error = err
		return outcome, err
	}

	payload := &envelope.Payload{}
	err = json.Unmarshal(outcome.EnvelopeContent.Payload.Content, payload)
	if err != nil {
		outcome.Error = err
		return outcome, err
	}

	if !content.Equal(payload.TargetArtifact, desc) {
		outcome.Error = errors.New("content descriptor mismatch")
	}
	return outcome, outcome.Error
}

func (v *verifier) processSignature(ctx context.Context, sigBlob []byte, envelopeMediaType string, trustPolicy *trustpolicy.TrustPolicy, pluginConfig map[string]string, outcome *notation.VerificationOutcome) error {
	logger := log.GetLogger(ctx)

	// verify integrity first. notation will always verify integrity no matter what the signing scheme is
	envContent, integrityResult := verifyIntegrity(sigBlob, envelopeMediaType, outcome)
	outcome.EnvelopeContent = envContent
	outcome.VerificationResults = append(outcome.VerificationResults, integrityResult)
	if integrityResult.Error != nil {
		logVerificationResult(logger, integrityResult)
		return integrityResult.Error
	}

	// check if we need to verify using a plugin
	var pluginCapabilities []proto.Capability
	verificationPluginName, err := getVerificationPlugin(&outcome.EnvelopeContent.SignerInfo)
	// use plugin, but getPluginName returns an error
	if err != nil && err != errExtendedAttributeNotExist {
		return err
	}
	var installedPlugin plugin.Plugin
	if verificationPluginName != "" {
		logger.Debugf("Finding verification plugin %s", verificationPluginName)
		if _, err := getVerificationPluginMinVersion(&outcome.EnvelopeContent.SignerInfo); err != nil && err != errExtendedAttributeNotExist {
			return notation.ErrorVerificationInconclusive{Msg: fmt.Sprintf("error while getting plugin minimum version, error: %s", err)}
		}
		// TODO verify the plugin's version is equal to or greater than `outcome.SignerInfo.SignedAttributes.HeaderVerificationPluginMinVersion`
		// https://github.com/notaryproject/notation-go/issues/102

		if v.pluginManager == nil {
			return notation.ErrorVerificationInconclusive{Msg: "plugin unsupported due to nil verifier.pluginManager"}
		}
		installedPlugin, err = v.pluginManager.Get(ctx, verificationPluginName)
		if err != nil {
			return notation.ErrorVerificationInconclusive{Msg: fmt.Sprintf("error while locating the verification plugin %q, make sure the plugin is installed successfully before verifying the signature. error: %s", verificationPluginName, err)}
		}

		// filter the "verification" capabilities supported by the installed plugin
		metadata, err := installedPlugin.GetMetadata(ctx, &proto.GetMetadataRequest{PluginConfig: pluginConfig})
		if err != nil {
			return err
		}

		for _, capability := range metadata.Capabilities {
			if capability == proto.CapabilityRevocationCheckVerifier || capability == proto.CapabilityTrustedIdentityVerifier {
				pluginCapabilities = append(pluginCapabilities, capability)
			}
		}

		if len(pluginCapabilities) == 0 {
			return notation.ErrorVerificationInconclusive{Msg: fmt.Sprintf("digital signature requires plugin %q with signature verification capabilities (%q and/or %q) installed", verificationPluginName, proto.CapabilityTrustedIdentityVerifier, proto.CapabilityRevocationCheckVerifier)}
		}
	}

	// verify x509 trust store based authenticity
	logger.Debug("Validating cert chain")
	authenticityResult := verifyAuthenticity(ctx, trustPolicy, v.trustStore, outcome)
	outcome.VerificationResults = append(outcome.VerificationResults, authenticityResult)
	logVerificationResult(logger, authenticityResult)
	if isCriticalFailure(authenticityResult) {
		return authenticityResult.Error
	}

	// verify x509 trusted identity based authenticity (only if notation needs to perform this verification rather than a plugin)
	if !slices.Contains(pluginCapabilities, proto.CapabilityTrustedIdentityVerifier) {
		logger.Debug("Validating trust identity")
		err = verifyX509TrustedIdentities(outcome.EnvelopeContent.SignerInfo.CertificateChain, trustPolicy)
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
	authenticTimestampResult := verifyAuthenticTimestamp(outcome)
	outcome.VerificationResults = append(outcome.VerificationResults, authenticTimestampResult)
	logVerificationResult(logger, authenticTimestampResult)
	if isCriticalFailure(authenticTimestampResult) {
		return authenticTimestampResult.Error
	}

	// verify revocation
	// check if we need to bypass the revocation check, since revocation can be skipped using a trust policy or a plugin may override the check
	if outcome.VerificationLevel.Enforcement[trustpolicy.TypeRevocation] != trustpolicy.ActionSkip &&
		!slices.Contains(pluginCapabilities, proto.CapabilityRevocationCheckVerifier) {
		logger.Debugf("Validating revocation (not implemented)")
		// TODO perform X509 revocation check (not in RC1)
		// https://github.com/notaryproject/notation-go/issues/110
	}

	// perform extended verification using verification plugin if present
	if installedPlugin != nil {
		var capabilitiesToVerify []proto.Capability
		for _, pc := range pluginCapabilities {
			// skip the revocation capability if the trust policy is configured to skip it
			if outcome.VerificationLevel.Enforcement[trustpolicy.TypeRevocation] == trustpolicy.ActionSkip && pc == proto.CapabilityRevocationCheckVerifier {
				logger.Debugf("Skipping the %v validation", pc)
				continue
			}
			capabilitiesToVerify = append(capabilitiesToVerify, pc)
		}

		if len(capabilitiesToVerify) > 0 {
			logger.Debugf("Executing verification plugin %q with capabilities %v", verificationPluginName, capabilitiesToVerify)
			response, err := executePlugin(ctx, installedPlugin, trustPolicy, capabilitiesToVerify, outcome.EnvelopeContent, pluginConfig)
			if err != nil {
				return err
			}

			return processPluginResponse(logger, capabilitiesToVerify, response, outcome)
		}
	}
	return nil
}

func processPluginResponse(logger log.Logger, capabilitiesToVerify []proto.Capability, response *proto.VerifySignatureResponse, outcome *notation.VerificationOutcome) error {
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
		case proto.CapabilityTrustedIdentityVerifier:
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
		case proto.CapabilityRevocationCheckVerifier:
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

func verifyAuthenticity(ctx context.Context, trustPolicy *trustpolicy.TrustPolicy, x509TrustStore truststore.X509TrustStore, outcome *notation.VerificationOutcome) *notation.ValidationResult {
	// verify authenticity
	trustCerts, err := loadX509TrustStores(ctx, outcome.EnvelopeContent.SignerInfo.SignedAttributes.SigningScheme, trustPolicy, x509TrustStore)

	if err != nil {
		return &notation.ValidationResult{
			Error:  notation.ErrorVerificationInconclusive{Msg: fmt.Sprintf("error while loading the trust store, %v", err)},
			Type:   trustpolicy.TypeAuthenticity,
			Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeAuthenticity],
		}
	}

	if len(trustCerts) < 1 {
		return &notation.ValidationResult{
			Error:  notation.ErrorVerificationInconclusive{Msg: "no trusted certificates are found to verify authenticity"},
			Type:   trustpolicy.TypeAuthenticity,
			Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeAuthenticity],
		}
	}
	_, err = signature.VerifyAuthenticity(&outcome.EnvelopeContent.SignerInfo, trustCerts)
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

func verifyAuthenticTimestamp(outcome *notation.VerificationOutcome) *notation.ValidationResult {
	invalidTimestamp := false
	var err error

	if signerInfo := outcome.EnvelopeContent.SignerInfo; signerInfo.SignedAttributes.SigningScheme == signature.SigningSchemeX509 {
		// TODO verify RFC3161 TSA signature if present (not in RC1)
		// https://github.com/notaryproject/notation-go/issues/78
		if len(signerInfo.UnsignedAttributes.TimestampSignature) == 0 {
			// if there is no TSA signature, then every certificate should be valid at the time of verification
			now := time.Now()
			for _, cert := range signerInfo.CertificateChain {
				if now.Before(cert.NotBefore) {
					invalidTimestamp = true
					err = fmt.Errorf("certificate %q is not valid yet, it will be valid from %q", cert.Subject, cert.NotBefore.Format(time.RFC1123Z))
					break
				}
				if now.After(cert.NotAfter) {
					invalidTimestamp = true
					err = fmt.Errorf("certificate %q is not valid anymore, it was expired at %q", cert.Subject, cert.NotAfter.Format(time.RFC1123Z))
					break
				}
			}
		}
	} else if signerInfo.SignedAttributes.SigningScheme == signature.SigningSchemeX509SigningAuthority {
		authenticSigningTime := signerInfo.SignedAttributes.SigningTime
		// TODO use authenticSigningTime from signerInfo
		// https://github.com/notaryproject/notation-core-go/issues/38
		for _, cert := range signerInfo.CertificateChain {
			if authenticSigningTime.Before(cert.NotBefore) || authenticSigningTime.After(cert.NotAfter) {
				invalidTimestamp = true
				err = fmt.Errorf("certificate %q was not valid when the digital signature was produced at %q", cert.Subject, authenticSigningTime.Format(time.RFC1123Z))
				break
			}
		}
	}

	if invalidTimestamp {
		return &notation.ValidationResult{
			Error:  err,
			Type:   trustpolicy.TypeAuthenticTimestamp,
			Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeAuthenticTimestamp],
		}
	}

	return &notation.ValidationResult{
		Type:   trustpolicy.TypeAuthenticTimestamp,
		Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeAuthenticTimestamp],
	}
}

func executePlugin(ctx context.Context, installedPlugin plugin.Plugin, trustPolicy *trustpolicy.TrustPolicy, capabilitiesToVerify []proto.Capability, envelopeContent *signature.EnvelopeContent, pluginConfig map[string]string) (*proto.VerifySignatureResponse, error) {
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

	signature := proto.Signature{
		CriticalAttributes: proto.CriticalAttributes{
			ContentType:          payloadInfo.ContentType,
			SigningScheme:        string(signerInfo.SignedAttributes.SigningScheme),
			Expiry:               &signerInfo.SignedAttributes.Expiry,
			AuthenticSigningTime: authenticSigningTime,
			ExtendedAttributes:   extendedAttributes,
		},
		UnprocessedAttributes: attributesToProcess,
		CertificateChain:      certChain,
	}

	policy := proto.TrustPolicy{
		TrustedIdentities:     trustPolicy.TrustedIdentities,
		SignatureVerification: capabilitiesToVerify,
	}

	req := &proto.VerifySignatureRequest{
		Signature:    signature,
		TrustPolicy:  policy,
		PluginConfig: pluginConfig,
	}
	return installedPlugin.VerifySignature(ctx, req)
}

func verifyX509TrustedIdentities(certs []*x509.Certificate, trustPolicy *trustpolicy.TrustPolicy) error {
	if slices.Contains(trustPolicy.TrustedIdentities, trustpolicyInternal.Wildcard) {
		return nil
	}

	var trustedX509Identities []map[string]string
	for _, identity := range trustPolicy.TrustedIdentities {
		identityPrefix, identityValue, found := strings.Cut(identity, ":")
		if !found {
			return fmt.Errorf("trust policy statement %q has trusted identity %q missing separator", trustPolicy.Name, identity)
		}

		// notation natively supports x509.subject identities only
		if identityPrefix == trustpolicyInternal.X509Subject {
			// identityValue cannot be empty
			if identityValue == "" {
				return fmt.Errorf("trust policy statement %q has trusted identity %q without an identity value", trustPolicy.Name, identity)
			}
			parsedSubject, err := pkix.ParseDistinguishedName(identityValue)
			if err != nil {
				return err
			}
			trustedX509Identities = append(trustedX509Identities, parsedSubject)
		}
	}

	if len(trustedX509Identities) == 0 {
		return fmt.Errorf("no x509 trusted identities are configured in the trust policy %q", trustPolicy.Name)
	}

	leafCert := certs[0] // trusted identities only supported on the leaf cert

	leafCertDN, err := pkix.ParseDistinguishedName(leafCert.Subject.String()) // parse the certificate subject following rfc 4514 DN syntax
	if err != nil {
		return fmt.Errorf("error while parsing the certificate subject from the digital signature. error : %q", err)
	}
	for _, trustedX509Identity := range trustedX509Identities {
		if pkix.IsSubsetDN(trustedX509Identity, leafCertDN) {
			return nil
		}
	}

	return fmt.Errorf("signing certificate from the digital signature does not match the X.509 trusted identities %q defined in the trust policy %q", trustedX509Identities, trustPolicy.Name)
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
