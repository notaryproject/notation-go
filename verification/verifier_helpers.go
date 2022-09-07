package verification

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/notaryproject/notation-go/plugin"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go/registry"
)

var errExtendedAttributeNotExist = errors.New("Extended attribute not exist")

var semVerRegEx = regexp.MustCompile("^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-((?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\\.(?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\\+([0-9a-zA-Z-]+(?:\\.[0-9a-zA-Z-]+)*))?$")

// isCriticalFailure checks whether a VerificationResult fails the entire signature verification workflow.
// signature verification workflow is considered failed if there is a VerificationResult with "Enforced" as the action but the result was unsuccessful
func isCriticalFailure(result *VerificationResult) bool {
	return result.Action == Enforced && !result.Success
}

func (v *Verifier) verifyIntegrity(sigBlob []byte, sigManifest registry.SignatureManifest, outcome *SignatureVerificationOutcome) (*signature.Payload, *signature.SignerInfo, *VerificationResult) {
	// parse the signature
	// TODO: this media type is pulled from registry
	// Do we need to check the media type?
	sigEnv, err := signature.ParseEnvelope(sigManifest.Blob.MediaType, sigBlob)
	if err != nil {
		return nil, nil, &VerificationResult{
			Success: false,
			Error:   fmt.Errorf("unable to parse the digital signature, error : %s", err),
			Type:    Integrity,
			Action:  outcome.VerificationLevel.VerificationMap[Integrity],
		}
	}

	// verify integrity
	sigPayload, signerInfo, err := sigEnv.Verify()
	if err != nil {
		switch err.(type) {
		case *signature.SignatureEnvelopeNotFoundError, *signature.MalformedSignatureError, *signature.SignatureIntegrityError:
			return nil, nil, &VerificationResult{
				Success: false,
				Error:   err,
				Type:    Integrity,
				Action:  outcome.VerificationLevel.VerificationMap[Integrity],
			}
		default:
			// unexpected error
			return nil, nil, &VerificationResult{
				Success: false,
				Error:   ErrorVerificationInconclusive{msg: err.Error()},
				Type:    Integrity,
				Action:  outcome.VerificationLevel.VerificationMap[Integrity],
			}
		}
	}

	// integrity has been verified successfully
	return sigPayload, signerInfo, &VerificationResult{
		Success: true,
		Type:    Integrity,
		Action:  outcome.VerificationLevel.VerificationMap[Integrity],
	}
}

func (v *Verifier) verifyAuthenticity(trustPolicy *TrustPolicy, outcome *SignatureVerificationOutcome) *VerificationResult {
	// verify authenticity
	trustStores, err := loadX509TrustStores(outcome.SignerInfo.SignedAttributes.SigningScheme, trustPolicy, v.PathManager)

	if err != nil {
		return &VerificationResult{
			Success: false,
			Error:   ErrorVerificationInconclusive{msg: fmt.Sprintf("error while loading the trust store, %v", err)},
			Type:    Authenticity,
			Action:  outcome.VerificationLevel.VerificationMap[Authenticity],
		}
	}

	var trustCerts []*x509.Certificate
	for _, v := range trustStores {
		trustCerts = append(trustCerts, v.Certificates...)
	}
	if len(trustCerts) < 1 {
		return &VerificationResult{
			Success: false,
			Error:   ErrorVerificationInconclusive{msg: "no trusted certificates are found to verify authenticity"},
			Type:    Authenticity,
			Action:  outcome.VerificationLevel.VerificationMap[Authenticity],
		}
	}
	_, err = signature.VerifyAuthenticity(outcome.SignerInfo, trustCerts)
	if err != nil {
		switch err.(type) {
		case *signature.SignatureAuthenticityError:
			return &VerificationResult{
				Success: false,
				Error:   err,
				Type:    Authenticity,
				Action:  outcome.VerificationLevel.VerificationMap[Authenticity],
			}
		default:
			return &VerificationResult{
				Success: false,
				Error:   ErrorVerificationInconclusive{msg: "authenticity verification failed with error : " + err.Error()},
				Type:    Authenticity,
				Action:  outcome.VerificationLevel.VerificationMap[Authenticity],
			}
		}
	} else {
		return &VerificationResult{
			Success: true,
			Type:    Authenticity,
			Action:  outcome.VerificationLevel.VerificationMap[Authenticity],
		}
	}
}

func (v *Verifier) verifyExpiry(outcome *SignatureVerificationOutcome) *VerificationResult {
	if !outcome.SignerInfo.SignedAttributes.Expiry.IsZero() && !time.Now().Before(outcome.SignerInfo.SignedAttributes.Expiry) {
		return &VerificationResult{
			Success: false,
			Error:   fmt.Errorf("digital signature has expired on %q", outcome.SignerInfo.SignedAttributes.Expiry.Format(time.RFC1123Z)),
			Type:    Expiry,
			Action:  outcome.VerificationLevel.VerificationMap[Expiry],
		}
	} else {
		return &VerificationResult{
			Success: true,
			Type:    Expiry,
			Action:  outcome.VerificationLevel.VerificationMap[Expiry],
		}
	}
}

func (v *Verifier) verifyAuthenticTimestamp(outcome *SignatureVerificationOutcome) *VerificationResult {
	invalidTimestamp := false
	var err error

	if outcome.SignerInfo.SignedAttributes.SigningScheme == signature.SigningSchemeX509 {
		// TODO verify RFC3161 TSA signature if present (not in RC1)
		// https://github.com/notaryproject/notation-go/issues/78
		if len(outcome.SignerInfo.UnsignedAttributes.TimestampSignature) == 0 {
			// if there is no TSA signature, then every certificate should be valid at the time of verification
			now := time.Now()
			for _, cert := range outcome.SignerInfo.CertificateChain {
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
	} else if outcome.SignerInfo.SignedAttributes.SigningScheme == signature.SigningSchemeX509SigningAuthority {
		authenticSigningTime := outcome.SignerInfo.SignedAttributes.SigningTime
		// TODO use authenticSigningTime from signerInfo
		// https://github.com/notaryproject/notation-core-go/issues/38
		for _, cert := range outcome.SignerInfo.CertificateChain {
			if authenticSigningTime.Before(cert.NotBefore) || authenticSigningTime.After(cert.NotAfter) {
				invalidTimestamp = true
				err = fmt.Errorf("certificate %q was not valid when the digital signature was produced at %q", cert.Subject, authenticSigningTime.Format(time.RFC1123Z))
				break
			}
		}
	}

	if invalidTimestamp {
		return &VerificationResult{
			Success: false,
			Error:   err,
			Type:    AuthenticTimestamp,
			Action:  outcome.VerificationLevel.VerificationMap[AuthenticTimestamp],
		}
	} else {
		return &VerificationResult{
			Success: true,
			Type:    AuthenticTimestamp,
			Action:  outcome.VerificationLevel.VerificationMap[AuthenticTimestamp],
		}
	}
}

// verifyX509TrustedIdentities verified x509 trusted identities. This functions uses the VerificationResult from x509 trust store verification and modifies it
func (v *Verifier) verifyX509TrustedIdentities(trustPolicy *TrustPolicy, outcome *SignatureVerificationOutcome, authenticityResult *VerificationResult) {
	// verify trusted identities
	err := verifyX509TrustedIdentities(outcome.SignerInfo.CertificateChain, trustPolicy)
	if err != nil {
		authenticityResult.Success = false
		authenticityResult.Error = err
	}
}

func verifyX509TrustedIdentities(certs []*x509.Certificate, trustPolicy *TrustPolicy) error {
	if isPresent(wildcard, trustPolicy.TrustedIdentities) {
		return nil
	}

	var trustedX509Identities []map[string]string
	for _, identity := range trustPolicy.TrustedIdentities {
		i := strings.Index(identity, ":")

		identityPrefix := identity[:i]
		identityValue := identity[i+1:]

		if identityPrefix == x509Subject {
			parsedSubject, err := parseDistinguishedName(identityValue)
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

	leafCertDN, err := parseDistinguishedName(leafCert.Subject.String()) // parse the certificate subject following rfc 4514 DN syntax
	if err != nil {
		return fmt.Errorf("error while parsing the certificate subject from the digital signature. error : %q", err)
	}
	for _, trustedX509Identity := range trustedX509Identities {
		if isSubsetDN(trustedX509Identity, leafCertDN) {
			return nil
		}
	}

	return fmt.Errorf("signing certificate from the digital signature does not match the X.509 trusted identities %q defined in the trust policy %q", trustedX509Identities, trustPolicy.Name)
}

func (v *Verifier) executePlugin(ctx context.Context, trustPolicy *TrustPolicy, capabilitiesToVerify []plugin.VerificationCapability, signerInfo *signature.SignerInfo, payloadInfo *signature.Payload) (*plugin.VerifySignatureResponse, error) {
	verificationPluginName, err := getVerificationPlugin(signerInfo)
	if err != nil {
		return nil, err
	}
	var attributesToProcess []string
	extendedAttributes := make(map[string]interface{})

	// pass extended critical attributes to the plugin's verify-signature command
	for _, attr := range signerInfo.SignedAttributes.ExtendedAttributes {
		if attr.Critical {
			extendedAttributes[attr.Key] = attr.Value
			attributesToProcess = append(attributesToProcess, attr.Key)
		}
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
		PluginConfig:    getPluginConfig(ctx),
	}
	pluginRunner, err := v.PluginManager.Runner(verificationPluginName)
	if err != nil {
		return nil, ErrorVerificationInconclusive{msg: fmt.Sprintf("error while loading the verification plugin %q: %s", verificationPluginName, err)}
	}
	out, err := pluginRunner.Run(ctx, request)
	if err != nil {
		return nil, ErrorVerificationInconclusive{msg: fmt.Sprintf("error while running the verification plugin %q: %s", verificationPluginName, err)}
	}

	response, ok := out.(*plugin.VerifySignatureResponse)
	if !ok {
		return nil, ErrorVerificationInconclusive{msg: fmt.Sprintf("verification plugin %q returned unexpected response : %q", verificationPluginName, out)}
	}

	return response, nil
}

// extractCriticalStringExtendedAttribute extracts a critical string Extended attribute from a signer
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
		return "", fmt.Errorf("%v from Extended attribute is not a string", key)
	}
	return val, nil
}

// getVerificationPlugin get plugin name from the Extended attributes
func getVerificationPlugin(signerInfo *signature.SignerInfo) (string, error) {
	name, err := extractCriticalStringExtendedAttribute(signerInfo, VerificationPlugin)
	if err != nil {
		return "", err
	}
	// not an empty string
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("%v from Extended attribute is an empty string", VerificationPlugin)
	}
	return name, nil
}

func getVerificationPluginMinVersion(signerInfo *signature.SignerInfo) (string, error) {
	version, err := extractCriticalStringExtendedAttribute(signerInfo, VerificationPluginMinVersion)
	if err != nil {
		return "", err
	}
	// empty version
	if strings.TrimSpace(version) == "" {
		return "", fmt.Errorf("%v from Extended attribute is an empty string", VerificationPluginMinVersion)
	}
	if !semVerRegEx.MatchString(version) {
		return "", fmt.Errorf("%v from Extended attribute is not a is not valid SemVer", VerificationPluginMinVersion)
	}
	return version, nil
}
