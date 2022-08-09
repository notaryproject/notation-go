package verification

import (
	"context"
	"crypto/x509"
	"fmt"
	nsigner "github.com/notaryproject/notation-core-go/signer"
	"github.com/notaryproject/notation-go/plugin"
	"github.com/notaryproject/notation-go/registry"
	"strings"
	"time"
)

// isCriticalFailure checks whether a VerificationResult fails the entire signature verification workflow.
// signature verification workflow is considered failed if there is a VerificationResult with "Enforced" as the action but the result was unsuccessful
func isCriticalFailure(result *VerificationResult) bool {
	return result.Action == Enforced && !result.Success
}

func (v *Verifier) verifyIntegrity(sigBlob []byte, sigManifest registry.SignatureManifest, outcome *SignatureVerificationOutcome) (*nsigner.SignerInfo, *VerificationResult) {
	// parse the signature
	sigEnv, err := nsigner.NewSignatureEnvelopeFromBytes(sigBlob, nsigner.SignatureMediaType(sigManifest.Blob.MediaType))
	if err != nil {
		return nil, &VerificationResult{
			Success: false,
			Error:   fmt.Errorf("unable to parse the digital signature, error : %s", err),
			Type:    Integrity,
			Action:  outcome.VerificationLevel.VerificationMap[Integrity],
		}
	}

	// verify integrity
	signerInfo, err := sigEnv.Verify()
	if err != nil {
		switch err.(type) {
		case nsigner.SignatureNotFoundError, nsigner.MalformedSignatureError, nsigner.SignatureIntegrityError:
			return nil, &VerificationResult{
				Success: false,
				Error:   err,
				Type:    Integrity,
				Action:  outcome.VerificationLevel.VerificationMap[Integrity],
			}
		default:
			// unexpected error
			return nil, &VerificationResult{
				Success: false,
				Error:   ErrorVerificationInconclusive{msg: err.Error()},
				Type:    Integrity,
				Action:  outcome.VerificationLevel.VerificationMap[Integrity],
			}
		}
	}

	// integrity has been verified successfully
	return signerInfo, &VerificationResult{
		Success: true,
		Type:    Integrity,
		Action:  outcome.VerificationLevel.VerificationMap[Integrity],
	}
}

func (v *Verifier) verifyAuthenticity(trustPolicy *TrustPolicy, outcome *SignatureVerificationOutcome) *VerificationResult {
	// verify authenticity
	trustStores, err := loadX509TrustStores(outcome.SignerInfo.SigningScheme, trustPolicy, v.PathManager)

	if err != nil {
		return &VerificationResult{
			Success: false,
			Error:   ErrorVerificationInconclusive{msg: fmt.Sprintf("error while loading the trust store, %v", err)},
			Type:    Authenticity,
			Action:  outcome.VerificationLevel.VerificationMap[Authenticity],
		}
	}

	// filter trust certificates based on trust store prefix
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

	_, err = nsigner.VerifyAuthenticity(outcome.SignerInfo, trustCerts)
	if err != nil {
		switch err.(type) {
		case nsigner.SignatureAuthenticityError:
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

	if outcome.SignerInfo.SigningScheme == nsigner.SigningSchemeX509Default {
		// TODO verify RFC3161 TSA signature if present (not in RC1)
		if len(outcome.SignerInfo.TimestampSignature) == 0 {
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
	} else if outcome.SignerInfo.SigningScheme == nsigner.SigningSchemeX509SigningAuthority {
		signingTime := outcome.SignerInfo.SignedAttributes.SigningTime
		for _, cert := range outcome.SignerInfo.CertificateChain {
			if signingTime.Before(cert.NotBefore) || signingTime.After(cert.NotAfter) {
				invalidTimestamp = true
				err = fmt.Errorf("certificate %q was not valid when the digital signature was produced at %q", cert.Subject, signingTime.Format(time.RFC1123Z))
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

func (v *Verifier) executePlugin(ctx context.Context, trustPolicy *TrustPolicy, capabilitiesToVerify []plugin.VerificationCapability, signerInfo *nsigner.SignerInfo) (*plugin.VerifySignatureResponse, error) {
	verificationPluginName := signerInfo.SignedAttributes.VerificationPlugin
	var attributesToProcess []string
	extendedAttributes := make(map[string]interface{})

	for _, attr := range signerInfo.SignedAttributes.ExtendedAttributes {
		extendedAttributes[attr.Key] = attr.Value
		if attr.Critical {
			attributesToProcess = append(attributesToProcess, attr.Key)
		}
	}

	var certChain [][]byte
	for _, cert := range signerInfo.CertificateChain {
		certChain = append(certChain, cert.Raw)
	}

	signature := plugin.Signature{
		CriticalAttributes: plugin.CriticalAttributes{
			ContentType:        string(signerInfo.PayloadContentType),
			SigningScheme:      string(signerInfo.SigningScheme),
			Expiry:             &signerInfo.SignedAttributes.Expiry,
			ExtendedAttributes: extendedAttributes,
		},
		UnprocessedAttributes: attributesToProcess,
		CertificateChain:      certChain,
	}

	policy := plugin.TrustPolicy{
		TrustedIdentities:     trustPolicy.TrustedIdentities,
		SignatureVerification: capabilitiesToVerify,
	}

	pluginConfig := map[string]string{}
	request := &plugin.VerifySignatureRequest{
		ContractVersion: plugin.ContractVersion,
		Signature:       signature,
		TrustPolicy:     policy,
		PluginConfig:    getPluginConfig(ctx, pluginConfig),
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
