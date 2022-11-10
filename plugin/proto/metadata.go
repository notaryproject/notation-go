package proto

import "errors"

// GetMetadataRequest contains the parameters passed in a get-plugin-metadata
// request.
type GetMetadataRequest struct {
	PluginConfig map[string]string `json:"pluginConfig,omitempty"`
}

func (GetMetadataRequest) Command() Command {
	return CommandGetMetadata
}

// GetMetadataResponse provided by the plugin.
type GetMetadataResponse struct {
	Name                      string       `json:"name"`
	Description               string       `json:"description"`
	Version                   string       `json:"version"`
	URL                       string       `json:"url"`
	SupportedContractVersions []string     `json:"supportedContractVersions"`
	Capabilities              []Capability `json:"capabilities"`
}

// Validate checks if the metadata is correctly populated.
func (resp *GetMetadataResponse) Validate() error {
	if resp.Name == "" {
		return errors.New("empty name")
	}
	if resp.Description == "" {
		return errors.New("empty description")
	}
	if resp.Version == "" {
		return errors.New("empty version")
	}
	if resp.URL == "" {
		return errors.New("empty url")
	}
	if len(resp.Capabilities) == 0 {
		return errors.New("empty capabilities")
	}
	if len(resp.SupportedContractVersions) == 0 {
		return errors.New("empty supported contract versions")
	}
	return nil
}

// HasCapability return true if the metadata states that the
// capability is supported.
// Returns true if capability is empty.
func (resp *GetMetadataResponse) HasCapability(capability Capability) bool {
	if capability == "" {
		return true
	}
	for _, c := range resp.Capabilities {
		if c == capability {
			return true
		}
	}
	return false
}

// SupportsContract return true if the metadata states that the
// contract version is supported.
func (resp *GetMetadataResponse) SupportsContract(ver string) bool {
	for _, v := range resp.SupportedContractVersions {
		if v == ver {
			return true
		}
	}
	return false
}
