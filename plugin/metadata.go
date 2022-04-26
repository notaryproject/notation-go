package plugin

import "errors"

// Metadata provided by the plugin.
type Metadata struct {
	Name                      string   `json:"name"`
	Description               string   `json:"description"`
	Version                   string   `json:"version"`
	URL                       string   `json:"url"`
	SupportedContractVersions []string `json:"supported-contract-versions"`
	Capabilities              []string `json:"capabilities"`
}

// Validate checks if the metadata is correctly populated.
func (m *Metadata) Validate() error {
	if m.Name == "" {
		return errors.New("name must not be empty")
	}
	if m.Description == "" {
		return errors.New("description name must not be empty")
	}
	if m.Version == "" {
		return errors.New("version must not be empty")
	}
	if m.URL == "" {
		return errors.New("url must not be empty")
	}
	if len(m.Capabilities) == 0 {
		return errors.New("capabilities must not be empty")
	}
	if len(m.SupportedContractVersions) == 0 {
		return errors.New("supported contract versions must not be empty")
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
