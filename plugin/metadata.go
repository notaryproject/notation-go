package plugin

import "errors"

// Metadata provided by the plugin.
type Metadata struct {
	Name                      string   `json:"name"`
	Description               string   `json:"description"`
	Version                   string   `json:"version"`
	URL                       string   `json:"url"`
	SupportedContractVersions []string `json:"supportedContractVersions"`
	Capabilities              []string `json:"capabilities"`
}

// Validate checks if the metadata is correctly populated.
func (m *Metadata) Validate() error {
	if m.Name == "" {
		return errors.New("empty name")
	}
	if m.Description == "" {
		return errors.New("empty description")
	}
	if m.Version == "" {
		return errors.New("empty version")
	}
	if m.URL == "" {
		return errors.New("empty url")
	}
	if len(m.Capabilities) == 0 {
		return errors.New("empty capabilities")
	}
	if len(m.SupportedContractVersions) == 0 {
		return errors.New("empty supported contract versions")
	}
	return nil
}

// HasCapability return true if the metadata states that the
// capability is supported.
func (m *Metadata) HasCapability(capability string) bool {
	for _, c := range m.Capabilities {
		if c == capability {
			return true
		}
	}
	return false
}

// SupportsContract return true if the metadata states that the
// major contract version is supported.
func (m *Metadata) SupportsContract(major string) bool {
	for _, v := range m.SupportedContractVersions {
		if v == major {
			return true
		}
	}
	return false
}
