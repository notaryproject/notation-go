package proto

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
