package pkix

import (
	"fmt"

	ldapv3 "github.com/go-ldap/ldap/v3"
)

// ParseDistinguishedName parses a DN name and validates Notary V2 rules
func ParseDistinguishedName(name string) (map[string]string, error) {
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

// IsSubsetDN returns true if dn1 is a subset of dn2 i.e. every key/value pair of dn1 has a matching key/value pair in dn2, otherwise returns false
func IsSubsetDN(dn1 map[string]string, dn2 map[string]string) bool {
	for key := range dn1 {
		if dn1[key] != dn2[key] {
			return false
		}
	}
	return true
}
