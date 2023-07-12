// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
