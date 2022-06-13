package verification

import (
	"crypto/x509"
	"fmt"
	"strings"
)

type Verifier struct {
	PolicyDocument  *PolicyDocument
	X509TrustStores []*X509TrustStore
}

func NewVerifier(policyDocument *PolicyDocument, x509TrustStores []*X509TrustStore) *Verifier {
	return &Verifier{
		PolicyDocument:  policyDocument,
		X509TrustStores: x509TrustStores,
	}
}

func (v *Verifier) Verify(registryUri string) error {
	i := strings.LastIndex(registryUri, ":")
	if i < 0 {
		return fmt.Errorf("registry URI %q could not be parsed, make sure it is the fully qualified registry URI without the scheme/protocol. e.g domain.com:80/my/repository:mytag", registryUri)
	}

	registryScope := registryUri[:i]
	if err := validateRegistryScopeFormat(registryScope); err != nil {
		return err
	}

	/*
		[DONE] Find the applicable trust policy, if none, return error
		If signatureVerification is skip, then return without an error
		Retrieve signature manifests
		Return error if no signature manifests
		For each signature manifest
			Check the root cert hash is present in trust store hashes, otherwise fail early
			Retrieve the signature envelope
			Verify integrity
				Signing cert produced the signature
				Chain from signing cert to root cert is valid
			Verify Authenticity
				[DONE] Verify root of trust is established
				[DONE] Verify trusted identites match from the policy
			Verify expiry time of the signature is in the future
			(NOT in RC1) Verify timestamping signature if present
			(NOT in RC1) Verify revocation
			Invoke plugin for extended verification
	*/

	// No error
	return nil
}

func verifyX509TrustedIdentities(certs []*x509.Certificate, trustPolicy TrustPolicy) error {
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

	for _, cert := range certs {
		certDN, err := parseDistinguishedName(cert.Subject.String()) // parse the certificate subject following rfc 4514 DN syntax
		if err != nil {
			return fmt.Errorf("error while parsing the certificate subject from the digital signature. Error : %q", err)
		}
		for _, trustedX509Identity := range trustedX509Identities {
			if isOverlappingDN(trustedX509Identity, certDN) {
				return nil
			}
		}
	}

	return fmt.Errorf("certificates from the digital signature do not match the X509 trusted identites %q defined in the trust policy %q", trustedX509Identities, trustPolicy.Name)
}
