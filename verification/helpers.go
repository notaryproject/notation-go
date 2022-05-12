package verification

import (
	"fmt"
	"regexp"
	"strings"

	ldapv3 "github.com/go-ldap/ldap/v3"
)

// isPresent is a utility function to check if a string exists in an array
func isPresent(val string, values []string) bool {
	for _, v := range values {
		if v == val {
			return true
		}
	}
	return false
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

// validateDistinguishedName validates if a DN name parsable and follows Notary V2 rules
func validateDistinguishedName(name string) error {
	mandatoryFields := []string{"C", "ST", "O"}
	rDnCount := make(map[string]int)
	dn, err := ldapv3.ParseDN(name)

	if err != nil {
		return fmt.Errorf("distinguished name (DN) %q is not valid, make sure it is following rfc4514 standard", name)
	}

	for _, rdn := range dn.RDNs {
		for _, attribute := range rdn.Attributes {
			rDnCount[attribute.Type]++
		}
	}

	// Verify there are no duplicate RDNs (multi-valdued RDNs are not supported)
	for key := range rDnCount {
		if rDnCount[key] > 1 {
			return fmt.Errorf("distinguished name (DN) %q has duplicate RDNs, DN can only have unique RDNs", name)
		}
	}

	// Verify mandatory fields are present
	for _, field := range mandatoryFields {
		if rDnCount[field] != 1 {
			return fmt.Errorf("distinguished name (DN) %q has no mandatory RDN for %q", name, field)
		}
	}
	// No errors
	return nil
}
