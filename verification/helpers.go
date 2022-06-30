package verification

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	ldapv3 "github.com/go-ldap/ldap/v3"
)

func loadPolicyDocument(policyDocumentPath string) (*PolicyDocument, error) {
	var policyDocument *PolicyDocument = &PolicyDocument{}
	jsonFile, err := os.Open(policyDocumentPath)
	if err != nil {
		return nil, err
	}
	defer jsonFile.Close()
	err = json.NewDecoder(jsonFile).Decode(policyDocument)
	if err != nil {
		return nil, err
	}
	return policyDocument, nil
}

func loadX509TrustStores(policyDocument *PolicyDocument, trustStoreBasePath string) (map[string]*X509TrustStore, error) {
	var result = make(map[string]*X509TrustStore)
	for _, trustPolicy := range policyDocument.TrustPolicies {
		for _, trustStore := range trustPolicy.TrustStores {
			if result[trustStore] != nil {
				// we loaded this trust store already
				continue
			}
			i := strings.Index(trustStore, ":")
			prefix := trustStore[:i]
			name := trustStore[i+1:]
			x509TrustStore, err := LoadX509TrustStore(filepath.Join(trustStoreBasePath, prefix, name))
			if err != nil {
				return nil, err
			}
			result[trustStore] = x509TrustStore
		}
	}
	return result, nil
}

// isPresent is a utility function to check if a string exists in an array
func isPresent(val string, values []string) bool {
	for _, v := range values {
		if v == val {
			return true
		}
	}
	return false
}

func getArtifactPathFromUri(artifactUri string) (string, error) {
	// TODO support more types of URI like "domain.com/repository", "domain.com/repository:tag", "domain.com/repository@sha256:digest"
	i := strings.LastIndex(artifactUri, ":")
	if i < 0 {
		return "", fmt.Errorf("artifact URI %q could not be parsed, make sure it is the fully qualified OCI artifact URI without the scheme/protocol. e.g domain.com:80/my/repository:digest", artifactUri)
	}

	artifactPath := artifactUri[:i]
	if err := validateRegistryScopeFormat(artifactPath); err != nil {
		return "", err
	}
	return artifactPath, nil
}

func getArtifactDigestFromUri(artifactUri string) (string, error) {
	i := strings.LastIndex(artifactUri, ":")
	if i < 0 {
		return "", fmt.Errorf("artifact URI %q could not be parsed, make sure it is the fully qualified OCI artifact URI without the scheme/protocol. e.g domain.com:80/my/repository:digest", artifactUri)
	}

	artifactDigest := artifactUri[i+1:]
	if artifactDigest == "" {
		return "", fmt.Errorf("artifact URI %q has an invalid digest %q, make sure the URI is the fully qualified OCI artifact URI without the scheme/protocol. e.g domain.com:80/my/repository:digest", artifactUri, artifactDigest)
	}
	return artifactDigest, nil
}

// validateRegistryScopeFormat validates if a scope is following the format defined in distribution spec
func validateRegistryScopeFormat(scope string) error {
	// Domain and Repository regexes are adapted from distribution implementation
	// https://github.com/distribution/distribution/blob/main/reference/regexp.go#L31
	domainRegexp := regexp.MustCompile(`^(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])(?:(?:\.(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]))+)?(?::[0-9]+)?$`)
	repositoryRegexp := regexp.MustCompile(`^[a-z0-9]+(?:(?:(?:[._]|__|[-]*)[a-z0-9]+)+)?(?:(?:/[a-z0-9]+(?:(?:(?:[._]|__|[-]*)[a-z0-9]+)+)?)+)?$`)
	errorMessage := "registry scope %q is not valid, make sure it is the fully qualified registry URL without the scheme/protocol. e.g domain.com/my/repository"
	firstSlash := strings.Index(scope, "/")
	if firstSlash < 0 {
		return fmt.Errorf(errorMessage, scope)
	}
	domain := scope[:firstSlash]
	repository := scope[firstSlash+1:]

	if domain == "" || repository == "" || !domainRegexp.MatchString(domain) || !repositoryRegexp.MatchString(repository) {
		return fmt.Errorf(errorMessage, scope)
	}

	// No errors
	return nil
}

// parseDistinguishedName parses a DN name and validates Notary V2 rules
func parseDistinguishedName(name string) (map[string]string, error) {
	mandatoryFields := []string{"C", "ST", "O"}
	attrKeyValue := make(map[string]string)
	dn, err := ldapv3.ParseDN(name)

	if err != nil {
		return nil, fmt.Errorf("distinguished name (DN) %q is not valid, it must contain 'C', 'ST', and 'O' RDN attributes at a minimum, and follow RFC 4514 standard", name)
	}

	for _, rdn := range dn.RDNs {

		// multi-valued RDNs are not supported (TODO: add spec reference here)
		if len(rdn.Attributes) > 1 {
			return nil, fmt.Errorf("distinguished name (DN) %q has multi-valued RDN attributes, remove multi-valued RDN attributes as they are not supported", name)
		}
		for _, attribute := range rdn.Attributes {
			if attrKeyValue[attribute.Type] == "" {
				attrKeyValue[attribute.Type] = attribute.Value
			} else {
				return nil, fmt.Errorf("distinguished name (DN) %q has duplicate RDN attribute for %q, DN can only have unique RDN attributes", name, attribute.Type)
			}
		}
	}

	// Verify mandatory fields are present
	for _, field := range mandatoryFields {
		if attrKeyValue[field] == "" {
			return nil, fmt.Errorf("distinguished name (DN) %q has no mandatory RDN attribute for %q, it must contain 'C', 'ST', and 'O' RDN attributes at a minimum", name, field)
		}
	}
	// No errors
	return attrKeyValue, nil
}

func validateOverlappingDNs(policyName string, parsedDNs []parsedDN) error {
	for i, dn1 := range parsedDNs {
		for j, dn2 := range parsedDNs {
			if i != j && isSubsetDN(dn1.ParsedMap, dn2.ParsedMap) {
				return fmt.Errorf("trust policy statement %q has overlapping x509 trustedIdentities, %q overlaps with %q", policyName, dn1.RawString, dn2.RawString)
			}
		}
	}

	return nil
}

// isSubsetDN returns true if dn1 is a subset of dn2 i.e. every key/value pair of dn1 has a matching key/value pair in dn2, otherwise returns false
func isSubsetDN(dn1 map[string]string, dn2 map[string]string) bool {
	for key := range dn1 {
		if dn1[key] != dn2[key] {
			return false
		}
	}
	return true
}
