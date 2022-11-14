package verifier

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/internal/pkix"
	"github.com/notaryproject/notation-go/internal/slice"
	trustpolicyInternal "github.com/notaryproject/notation-go/internal/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
)

const (
	// HeaderVerificationPlugin specifies the name of the verification plugin that should be used to verify the signature.
	HeaderVerificationPlugin = "io.cncf.notary.verificationPlugin"

	// HeaderVerificationPluginMinVersion specifies the minimum version of the verification plugin that should be used to verify the signature.
	HeaderVerificationPluginMinVersion = "io.cncf.notary.verificationPluginMinVersion"
)

// VerificationPluginHeaders specifies headers of a verification plugin
var VerificationPluginHeaders = []string{
	HeaderVerificationPlugin,
	HeaderVerificationPluginMinVersion,
}

var errExtendedAttributeNotExist = errors.New("extended attribute not exist")

var semVerRegEx = regexp.MustCompile(`^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-((?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\\.(?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\\+([0-9a-zA-Z-]+(?:\\.[0-9a-zA-Z-]+)*))?$`)

func loadX509TrustStores(ctx context.Context, scheme signature.SigningScheme, policy *trustpolicy.TrustPolicy) ([]*x509.Certificate, error) {
	var typeToLoad truststore.Type
	switch scheme {
	case signature.SigningSchemeX509:
		typeToLoad = truststore.TypeCA
	case signature.SigningSchemeX509SigningAuthority:
		typeToLoad = truststore.TypeSigningAuthority
	default:
		return nil, fmt.Errorf("unrecognized signing scheme %q", scheme)
	}

	// TODO: create a package at internal/container/set for a set implementation
	// https://github.com/notaryproject/notation-go/issues/203
	var processedStoreSet = make(map[string]struct{})
	var certificates []*x509.Certificate
	x509TrustStore := truststore.NewX509TrustStore(dir.ConfigFS())
	for _, trustStore := range policy.TrustStores {
		if _, ok := processedStoreSet[trustStore]; ok {
			// we loaded this trust store already
			continue
		}

		// TODO: replace strings.Index() with Strings.Cut()
		// https://github.com/notaryproject/notation-go/issues/204
		i := strings.Index(trustStore, ":")
		storeType := trustStore[:i]
		if typeToLoad != truststore.Type(storeType) {
			continue
		}
		name := trustStore[i+1:]
		certs, err := x509TrustStore.GetCertificates(ctx, typeToLoad, name)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certs...)
		processedStoreSet[trustStore] = struct{}{}
	}
	return certificates, nil
}

// isCriticalFailure checks whether a VerificationResult fails the entire signature verification workflow.
// signature verification workflow is considered failed if there is a VerificationResult with "Enforced" as the action but the result was unsuccessful
func isCriticalFailure(result *notation.ValidationResult) bool {
	return result.Action == trustpolicy.ActionEnforce && result.Error != nil
}

func verifyX509TrustedIdentitiesCore(certs []*x509.Certificate, trustPolicy *trustpolicy.TrustPolicy) error {
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
