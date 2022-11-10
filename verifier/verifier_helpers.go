package verifier

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/internal/pkix"
	"github.com/notaryproject/notation-go/internal/plugin"
	"github.com/notaryproject/notation-go/internal/slice"
	trustpolicyInternal "github.com/notaryproject/notation-go/internal/trustpolicy"
	sig "github.com/notaryproject/notation-go/signature"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
)

const (
	// HeaderVerificationPlugin specifies the name of the verification plugin that should be used to verify the signature.
	HeaderVerificationPlugin = "io.cncf.notary.verificationPlugin"

	// HeaderVerificationPluginMinVersion specifies the minimum version of the verification plugin that should be used to verify the signature.
	HeaderVerificationPluginMinVersion = "io.cncf.notary.verificationPluginMinVersion"
)

var VerificationPluginHeaders = []string{
	HeaderVerificationPlugin,
	HeaderVerificationPluginMinVersion,
}

var errExtendedAttributeNotExist = errors.New("extended attribute not exist")

var semVerRegEx = regexp.MustCompile(`^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-((?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\\.(?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\\+([0-9a-zA-Z-]+(?:\\.[0-9a-zA-Z-]+)*))?$`)

// isCriticalFailure checks whether a VerificationResult fails the entire signature verification workflow.
// signature verification workflow is considered failed if there is a VerificationResult with "Enforced" as the action but the result was unsuccessful
func isCriticalFailure(result *notation.ValidationResult) bool {
	return result.Action == trustpolicy.ActionEnforce && result.Error != nil
}

func (v *verifier) verifyIntegrity(sigBlob []byte, envelopeMediaType string, outcome *notation.VerificationOutcome) (*signature.EnvelopeContent, *notation.ValidationResult) {
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

	if err := sig.ValidatePayloadContentType(&envContent.Payload); err != nil {
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

func (v *verifier) verifyAuthenticity(ctx context.Context, trustPolicy *trustpolicy.TrustPolicy, outcome *notation.VerificationOutcome) *notation.ValidationResult {
	// verify authenticity
	trustCerts, err := loadX509TrustStores(ctx, outcome.EnvelopeContent.SignerInfo.SignedAttributes.SigningScheme, trustPolicy)

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
	} else {
		return &notation.ValidationResult{
			Type:   trustpolicy.TypeAuthenticity,
			Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeAuthenticity],
		}
	}
}

func (v *verifier) verifyExpiry(outcome *notation.VerificationOutcome) *notation.ValidationResult {
	if expiry := outcome.EnvelopeContent.SignerInfo.SignedAttributes.Expiry; !expiry.IsZero() && !time.Now().Before(expiry) {
		return &notation.ValidationResult{
			Error:  fmt.Errorf("digital signature has expired on %q", expiry.Format(time.RFC1123Z)),
			Type:   trustpolicy.TypeExpiry,
			Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeExpiry],
		}
	} else {
		return &notation.ValidationResult{
			Type:   trustpolicy.TypeExpiry,
			Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeExpiry],
		}
	}
}

func (v *verifier) verifyAuthenticTimestamp(outcome *notation.VerificationOutcome) *notation.ValidationResult {
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
	} else {
		return &notation.ValidationResult{
			Type:   trustpolicy.TypeAuthenticTimestamp,
			Action: outcome.VerificationLevel.Enforcement[trustpolicy.TypeAuthenticTimestamp],
		}
	}
}

// verifyX509TrustedIdentities verified x509 trusted identities. This functions uses the VerificationResult from x509 trust store verification and modifies it
func (v *verifier) verifyX509TrustedIdentities(trustPolicy *trustpolicy.TrustPolicy, outcome *notation.VerificationOutcome, authenticityResult *notation.ValidationResult) {
	// verify trusted identities
	err := verifyX509TrustedIdentities(outcome.EnvelopeContent.SignerInfo.CertificateChain, trustPolicy)
	if err != nil {
		authenticityResult.Error = err
	}
}

func verifyX509TrustedIdentities(certs []*x509.Certificate, trustPolicy *trustpolicy.TrustPolicy) error {
	if slice.Contains(trustPolicy.TrustedIdentities, trustpolicyInternal.Wildcard) {
		return nil
	}

	var trustedX509Identities []map[string]string
	for _, identity := range trustPolicy.TrustedIdentities {
		i := strings.Index(identity, ":")

		identityPrefix := identity[:i]
		identityValue := identity[i+1:]

		if identityPrefix == trustpolicyInternal.X509Subject {
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

func (v *verifier) executePlugin(ctx context.Context, trustPolicy *trustpolicy.TrustPolicy, capabilitiesToVerify []plugin.VerificationCapability, envelopeContent *signature.EnvelopeContent, pluginConfig map[string]string) (*plugin.VerifySignatureResponse, error) {
	signerInfo, payloadInfo := &envelopeContent.SignerInfo, envelopeContent.Payload
	verificationPluginName, err := getVerificationPlugin(signerInfo)
	if err != nil {
		return nil, err
	}
	var attributesToProcess []string
	extendedAttributes := make(map[string]interface{})

	for _, attr := range getNonPluginExtendedCriticalAttributes(signerInfo) {
		extendedAttributes[attr.Key.(string)] = attr.Value
		attributesToProcess = append(attributesToProcess, attr.Key.(string))
	}

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

	signature := plugin.Signature{
		CriticalAttributes: plugin.CriticalAttributes{
			ContentType:          payloadInfo.ContentType,
			SigningScheme:        string(signerInfo.SignedAttributes.SigningScheme),
			Expiry:               &signerInfo.SignedAttributes.Expiry,
			AuthenticSigningTime: authenticSigningTime,
			ExtendedAttributes:   extendedAttributes,
		},
		UnprocessedAttributes: attributesToProcess,
		CertificateChain:      certChain,
	}

	policy := plugin.TrustPolicy{
		TrustedIdentities:     trustPolicy.TrustedIdentities,
		SignatureVerification: capabilitiesToVerify,
	}

	request := &plugin.VerifySignatureRequest{
		ContractVersion: plugin.ContractVersion,
		Signature:       signature,
		TrustPolicy:     policy,
		PluginConfig:    pluginConfig,
	}
	pluginRunner, err := v.pluginManager.Runner(verificationPluginName)
	if err != nil {
		return nil, notation.ErrorVerificationInconclusive{Msg: fmt.Sprintf("error while loading the verification plugin %q: %s", verificationPluginName, err)}
	}
	out, err := pluginRunner.Run(ctx, request)
	if err != nil {
		return nil, notation.ErrorVerificationInconclusive{Msg: fmt.Sprintf("error while running the verification plugin %q: %s", verificationPluginName, err)}
	}

	response, ok := out.(*plugin.VerifySignatureResponse)
	if !ok {
		return nil, notation.ErrorVerificationInconclusive{Msg: fmt.Sprintf("verification plugin %q returned unexpected response : %q", verificationPluginName, out)}
	}

	return response, nil
}

func getNonPluginExtendedCriticalAttributes(signerInfo *signature.SignerInfo) []signature.Attribute {
	var criticalExtendedAttrs []signature.Attribute
	for _, attr := range signerInfo.SignedAttributes.ExtendedAttributes {
		attrStrKey, ok := attr.Key.(string)
		if ok && !slice.Contains(VerificationPluginHeaders, attrStrKey) { // filter the plugin extended attributes
			// TODO support other attribute types (COSE attribute keys can be numbers)
			criticalExtendedAttrs = append(criticalExtendedAttrs, attr)
		}
	}
	return criticalExtendedAttrs
}

// extractCriticalStringExtendedAttribute extracts a critical string Extended attribute from a signer.
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
	// empty version
	if strings.TrimSpace(version) == "" {
		return "", fmt.Errorf("%v from extended attribute is an empty string", HeaderVerificationPluginMinVersion)
	}
	if !semVerRegEx.MatchString(version) {
		return "", fmt.Errorf("%v from extended attribute is not a valid SemVer", HeaderVerificationPluginMinVersion)
	}
	return version, nil
}
