package verification

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go/registry"
)

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
		case *signature.SignatureNotFoundError, *signature.MalformedSignatureError, *signature.SignatureIntegrityError:
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

func (v *Verifier) verifyAuthenticity(trustStorePrefix TrustStorePrefix, trustPolicy *TrustPolicy, outcome *SignatureVerificationOutcome) *VerificationResult {
	// verify authenticity
	trustStores, err := loadX509TrustStores(trustPolicy, v.PathManager)

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
		if v.Prefix == string(trustStorePrefix) {
			trustCerts = append(trustCerts, v.Certificates...)
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
		// if X509 authenticity passes, then perform Trusted Identity based authenticity
		return v.verifyTrustedIdentities(trustPolicy, outcome)
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

func (v *Verifier) verifyTrustedIdentities(trustPolicy *TrustPolicy, outcome *SignatureVerificationOutcome) *VerificationResult {
	// verify trusted identities
	err := verifyX509TrustedIdentities(outcome.SignerInfo.CertificateChain, trustPolicy)
	if err != nil {
		return &VerificationResult{
			Success: false,
			Error:   err,
			Type:    Authenticity,
			Action:  outcome.VerificationLevel.VerificationMap[Authenticity],
		}
	} else {
		return &VerificationResult{
			Success: true,
			Type:    Authenticity,
			Action:  outcome.VerificationLevel.VerificationMap[Authenticity],
		}
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
