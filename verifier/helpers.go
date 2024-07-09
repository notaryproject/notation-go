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

package verifier

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/notaryproject/notation-core-go/revocation"
	revocationresult "github.com/notaryproject/notation-core-go/revocation/result"
	"github.com/notaryproject/notation-core-go/signature"
	nx509 "github.com/notaryproject/notation-core-go/x509"
	"github.com/notaryproject/notation-go"
	set "github.com/notaryproject/notation-go/internal/container"
	notationsemver "github.com/notaryproject/notation-go/internal/semver"
	"github.com/notaryproject/notation-go/internal/slices"
	"github.com/notaryproject/notation-go/log"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	"github.com/notaryproject/tspclient-go"
)

const (
	// HeaderVerificationPlugin specifies the name of the verification plugin
	// that should be used to verify the signature.
	HeaderVerificationPlugin = "io.cncf.notary.verificationPlugin"

	// HeaderVerificationPluginMinVersion specifies the minimum version of the
	// verification plugin that should be used to verify the signature.
	HeaderVerificationPluginMinVersion = "io.cncf.notary.verificationPluginMinVersion"
)

// VerificationPluginHeaders specifies headers of a verification plugin
var VerificationPluginHeaders = []string{
	HeaderVerificationPlugin,
	HeaderVerificationPluginMinVersion,
}

var errExtendedAttributeNotExist = errors.New("extended attribute not exist")

func loadX509TrustStores(ctx context.Context, scheme signature.SigningScheme, policyName string, trustStores []string, x509TrustStore truststore.X509TrustStore) ([]*x509.Certificate, error) {
	var typeToLoad truststore.Type
	switch scheme {
	case signature.SigningSchemeX509:
		typeToLoad = truststore.TypeCA
	case signature.SigningSchemeX509SigningAuthority:
		typeToLoad = truststore.TypeSigningAuthority
	default:
		return nil, truststore.TrustStoreError{Msg: fmt.Sprintf("error while loading the trust store, unrecognized signing scheme %q", scheme)}
	}
	return loadX509TrustStoresWithType(ctx, typeToLoad, policyName, trustStores, x509TrustStore)
}

// isCriticalFailure checks whether a VerificationResult fails the entire
// signature verification workflow.
// signature verification workflow is considered failed if there is a
// VerificationResult with "Enforced" as the action but the result was
// unsuccessful.
func isCriticalFailure(result *notation.ValidationResult) bool {
	return result.Action == trustpolicy.ActionEnforce && result.Error != nil
}

func getNonPluginExtendedCriticalAttributes(signerInfo *signature.SignerInfo) []signature.Attribute {
	var criticalExtendedAttrs []signature.Attribute
	for _, attr := range signerInfo.SignedAttributes.ExtendedAttributes {
		attrStrKey, ok := attr.Key.(string)
		// filter the plugin extended attributes
		if ok && !slices.Contains(VerificationPluginHeaders, attrStrKey) {
			// TODO support other attribute types
			// (COSE attribute keys can be numbers)
			criticalExtendedAttrs = append(criticalExtendedAttrs, attr)
		}
	}
	return criticalExtendedAttrs
}

// extractCriticalStringExtendedAttribute extracts a critical string Extended
// attribute from a signer.
func extractCriticalStringExtendedAttribute(signerInfo *signature.SignerInfo, key string) (string, error) {
	attr, err := signerInfo.ExtendedAttribute(key)
	// not exist
	if err != nil {
		return "", errExtendedAttributeNotExist
	}
	// not critical
	if !attr.Critical {
		return "", fmt.Errorf("%v is not a critical Extended attribute", key)
	}
	// not string
	val, ok := attr.Value.(string)
	if !ok {
		return "", fmt.Errorf("%v from extended attribute is not a string", key)
	}
	return val, nil
}

// getVerificationPlugin get plugin name from the Extended attributes.
func getVerificationPlugin(signerInfo *signature.SignerInfo) (string, error) {
	name, err := extractCriticalStringExtendedAttribute(signerInfo, HeaderVerificationPlugin)
	if err != nil {
		return "", err
	}
	// not an empty string
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("%v from extended attribute is an empty string", HeaderVerificationPlugin)
	}
	return name, nil
}

// getVerificationPlugin get plugin version from the Extended attributes.
func getVerificationPluginMinVersion(signerInfo *signature.SignerInfo) (string, error) {
	version, err := extractCriticalStringExtendedAttribute(signerInfo, HeaderVerificationPluginMinVersion)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(version) == "" {
		return "", fmt.Errorf("%v from extended attribute is an empty string", HeaderVerificationPluginMinVersion)
	}
	if !notationsemver.IsValid(version) {
		return "", fmt.Errorf("%v from extended attribute is not a valid SemVer", HeaderVerificationPluginMinVersion)
	}
	return version, nil
}

func loadX509TSATrustStores(ctx context.Context, scheme signature.SigningScheme, policyName string, trustStores []string, x509TrustStore truststore.X509TrustStore) ([]*x509.Certificate, error) {
	var typeToLoad truststore.Type
	switch scheme {
	case signature.SigningSchemeX509:
		typeToLoad = truststore.TypeTSA
	default:
		return nil, truststore.TrustStoreError{Msg: fmt.Sprintf("error while loading the TSA trust store, signing scheme must be notary.x509, but got %s", scheme)}
	}
	return loadX509TrustStoresWithType(ctx, typeToLoad, policyName, trustStores, x509TrustStore)
}

func loadX509TrustStoresWithType(ctx context.Context, trustStoreType truststore.Type, policyName string, trustStores []string, x509TrustStore truststore.X509TrustStore) ([]*x509.Certificate, error) {
	processedStoreSet := set.New[string]()
	var certificates []*x509.Certificate
	for _, trustStore := range trustStores {
		if processedStoreSet.Contains(trustStore) {
			// we loaded this trust store already
			continue
		}

		storeType, name, found := strings.Cut(trustStore, ":")
		if !found {
			return nil, truststore.TrustStoreError{Msg: fmt.Sprintf("error while loading the trust store, trust policy statement %q is missing separator in trust store value %q. The required format is <TrustStoreType>:<TrustStoreName>", policyName, trustStore)}
		}
		if trustStoreType != truststore.Type(storeType) {
			continue
		}

		certs, err := x509TrustStore.GetCertificates(ctx, trustStoreType, name)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certs...)
		processedStoreSet.Add(trustStore)
	}
	return certificates, nil
}

// isTSATrustStoreInPolicy checks if tsa trust store is configured in
// trust policy
func isTSATrustStoreInPolicy(policyName string, trustStores []string) (bool, error) {
	for _, trustStore := range trustStores {
		storeType, _, found := strings.Cut(trustStore, ":")
		if !found {
			return false, truststore.TrustStoreError{Msg: fmt.Sprintf("invalid trust policy statement: %q is missing separator in trust store value %q. The required format is <TrustStoreType>:<TrustStoreName>", policyName, trustStore)}
		}
		if truststore.Type(storeType) == truststore.TypeTSA {
			return true, nil
		}
	}
	return false, nil
}

// verifyTimestamp provides core verification logic of authentic timestamp under
// signing scheme `notary.x509`.
func verifyTimestamp(ctx context.Context, policyName string, trustStores []string, signatureVerification trustpolicy.SignatureVerification, x509TrustStore truststore.X509TrustStore, r revocation.Revocation, outcome *notation.VerificationOutcome) *notation.ValidationResult {
	logger := log.GetLogger(ctx)

	signerInfo := outcome.EnvelopeContent.SignerInfo
	performTimestampVerification := true
	// check if tsa trust store is configured in trust policy
	tsaEnabled, err := isTSATrustStoreInPolicy(policyName, trustStores)
	if err != nil {
		return &notation.ValidationResult{
			Error:  fmt.Errorf("failed to check tsa trust store configuration in turst policy with error: %w", err),
			Type:   trustpolicy.TypeAuthenticTimestamp,
			Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeAuthenticTimestamp],
		}
	}
	if !tsaEnabled {
		logger.Info("Timestamp verification disabled: no tsa trust store is configured in trust policy")
		performTimestampVerification = false
	}
	// check based on 'verifyTimestamp' field
	if performTimestampVerification &&
		signatureVerification.VerifyTimestamp == trustpolicy.OptionAfterCertExpiry {
		// check if signing cert chain has expired
		var expired bool
		for _, cert := range signerInfo.CertificateChain {
			if time.Now().After(cert.NotAfter) {
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
		timeOfVerification := time.Now()
		for _, cert := range signerInfo.CertificateChain {
			if timeOfVerification.Before(cert.NotBefore) {
				return &notation.ValidationResult{
					Error:  fmt.Errorf("verification time is before certificate %q validity period, it will be valid from %q", cert.Subject, cert.NotBefore.Format(time.RFC1123Z)),
					Type:   trustpolicy.TypeAuthenticTimestamp,
					Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeAuthenticTimestamp],
				}
			}
			if timeOfVerification.After(cert.NotAfter) {
				return &notation.ValidationResult{
					Error:  fmt.Errorf("verification time is after certificate %q validity period, it was expired at %q", cert.Subject, cert.NotAfter.Format(time.RFC1123Z)),
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
	// Performing timestamp verification
	// 1. Timestamp countersignature MUST be present
	logger.Info("Checking timestamp countersignature existence...")
	if len(signerInfo.UnsignedAttributes.TimestampSignature) == 0 {
		return &notation.ValidationResult{
			Error:  errors.New("no timestamp countersignature was found in the signature envelope"),
			Type:   trustpolicy.TypeAuthenticTimestamp,
			Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeAuthenticTimestamp],
		}
	}
	// 2. Verify the timestamp countersignature
	logger.Info("Verifying the timestamp countersignature...")
	signedToken, err := tspclient.ParseSignedToken(signerInfo.UnsignedAttributes.TimestampSignature)
	if err != nil {
		return &notation.ValidationResult{
			Error:  fmt.Errorf("failed to parse timestamp countersignature with error: %w", err),
			Type:   trustpolicy.TypeAuthenticTimestamp,
			Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeAuthenticTimestamp],
		}
	}
	info, err := signedToken.Info()
	if err != nil {
		return &notation.ValidationResult{
			Error:  fmt.Errorf("failed to get the timestamp TSTInfo with error: %w", err),
			Type:   trustpolicy.TypeAuthenticTimestamp,
			Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeAuthenticTimestamp],
		}
	}
	trustTSACerts, err := loadX509TSATrustStores(ctx, outcome.EnvelopeContent.SignerInfo.SignedAttributes.SigningScheme, policyName, trustStores, x509TrustStore)
	if err != nil {
		return &notation.ValidationResult{
			Error:  fmt.Errorf("failed to load tsa trust store with error: %w", err),
			Type:   trustpolicy.TypeAuthenticTimestamp,
			Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeAuthenticTimestamp],
		}
	}
	if len(trustTSACerts) == 0 {
		return &notation.ValidationResult{
			Error:  errors.New("no trusted TSA certificate found in trust store"),
			Type:   trustpolicy.TypeAuthenticTimestamp,
			Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeAuthenticTimestamp],
		}
	}
	rootCertPool := x509.NewCertPool()
	for _, trustedCerts := range trustTSACerts {
		rootCertPool.AddCert(trustedCerts)
	}
	timestamp, err := info.Validate(signerInfo.Signature)
	if err != nil {
		return &notation.ValidationResult{
			Error:  fmt.Errorf("failed to get timestamp from timestamp countersignature with error: %w", err),
			Type:   trustpolicy.TypeAuthenticTimestamp,
			Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeAuthenticTimestamp],
		}
	}
	tsaCertChain, err := signedToken.Verify(ctx, x509.VerifyOptions{
		CurrentTime: timestamp.Value,
		Roots:       rootCertPool,
	})
	if err != nil {
		return &notation.ValidationResult{
			Error:  fmt.Errorf("failed to verify the timestamp countersignature with error: %w", err),
			Type:   trustpolicy.TypeAuthenticTimestamp,
			Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeAuthenticTimestamp],
		}
	}
	// 3. Validate timestamping certificate chain
	logger.Info("Validating timestamping certificate chain...")
	if err := nx509.ValidateTimestampingCertChain(tsaCertChain); err != nil {
		return &notation.ValidationResult{
			Error:  fmt.Errorf("failed to validate the timestamping certificate chain with error: %w", err),
			Type:   trustpolicy.TypeAuthenticTimestamp,
			Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeAuthenticTimestamp],
		}
	}
	logger.Info("TSA identity is: ", tsaCertChain[0].Subject)
	// 4. Perform the timestamping certificate chain revocation check
	logger.Info("Checking timestamping certificate chain revocation...")
	certResults, err := r.Validate(tsaCertChain, timestamp.Value)
	if err != nil {
		return &notation.ValidationResult{
			Error:  fmt.Errorf("failed to check timestamping certificate chain revocation with error: %w", err),
			Type:   trustpolicy.TypeAuthenticTimestamp,
			Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeAuthenticTimestamp],
		}
	}
	finalResult, problematicCertSubject := revocationFinalResult(certResults, tsaCertChain, logger)
	switch finalResult {
	case revocationresult.ResultOK:
		logger.Debug("No verification impacting errors encountered while checking timestamping certificate chain revocation, status is OK")
	case revocationresult.ResultRevoked:
		return &notation.ValidationResult{
			Error:  fmt.Errorf("timestamping certificate with subject %q is revoked", problematicCertSubject),
			Type:   trustpolicy.TypeAuthenticTimestamp,
			Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeAuthenticTimestamp],
		}
	default:
		// revocationresult.ResultUnknown
		return &notation.ValidationResult{
			Error:  fmt.Errorf("timestamping certificate with subject %q revocation status is unknown", problematicCertSubject),
			Type:   trustpolicy.TypeAuthenticTimestamp,
			Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeAuthenticTimestamp],
		}
	}
	// 5. Check the timestamp against the signing certificate chain
	logger.Info("Checking the timestamp against the signing certificate chain...")
	logger.Infof("Timestamp range: [%v, %v]", timestamp.Value.Add(-timestamp.Accuracy), timestamp.Value.Add(timestamp.Accuracy))
	for _, cert := range signerInfo.CertificateChain {
		if !timestamp.BoundedAfter(cert.NotBefore) {
			return &notation.ValidationResult{
				Error:  fmt.Errorf("timestamp can be before certificate %q validity period, it will be valid from %q", cert.Subject, cert.NotBefore.Format(time.RFC1123Z)),
				Type:   trustpolicy.TypeAuthenticTimestamp,
				Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeAuthenticTimestamp],
			}
		}
		if !timestamp.BoundedBefore(cert.NotAfter) {
			return &notation.ValidationResult{
				Error:  fmt.Errorf("timestamp can be after certificate %q validity period, it was expired at %q", cert.Subject, cert.NotAfter.Format(time.RFC1123Z)),
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
