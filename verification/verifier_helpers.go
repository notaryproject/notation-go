package verification

import (
	"crypto/x509"
	"fmt"
	"strings"
)

// isFailureResult checks whether a VerificationResult fails the entire signature verification workflow.
// signature verification workflow is considered failed if there is a VerificationResult with "Enforced" as the action but the result was inconclusive (failed to verify) or unsuccessful
func isFailureResult(result VerificationResult) bool {
	return result.Action == Enforced && (result.FailedToVerify || !result.Success)
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
		return nil
	}

	leafCert := certs[0]

	leafCertDN, err := parseDistinguishedName(leafCert.Subject.String()) // parse the certificate subject following rfc 4514 DN syntax
	if err != nil {
		return fmt.Errorf("error while parsing the certificate subject from the digital signature. Error : %q", err)
	}
	for _, trustedX509Identity := range trustedX509Identities {
		if isSubsetDN(trustedX509Identity, leafCertDN) {
			return nil
		}
	}

	return fmt.Errorf("signing certificate from the digital signature does not match the X.509 trusted identities %q defined in the trust policy %q", trustedX509Identities, trustPolicy.Name)
}
