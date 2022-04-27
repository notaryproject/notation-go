package plugin

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
)

// Plugin represents a potential plugin with all it's metadata.
type Plugin struct {
	Metadata

	Path string `json:",omitempty"`

	// Err is non-nil if the plugin failed one of the candidate tests.
	Err error `json:",omitempty"`
}

// ErrNotFound by Manager.Get when the plugin is not found.
var ErrNotFound = errors.New("plugin not found")

// newPlugin determines if the given candidate is valid
// and returns a Plugin.
func newPlugin(cmder commander, binPath, name string) *Plugin {
	p := &Plugin{
		Path: binPath,
	}

	meta, err := cmder.Output(p.Path, "get-plugin-metadata")
	if err != nil {
		p.Err = fmt.Errorf("failed to fetch metadata: %w", err)
		return p
	}

	if err := json.Unmarshal(meta, &p.Metadata); err != nil {
		p.Err = fmt.Errorf("metadata can't be decoded: %w", err)
		return p
	}
	if p.Name != name {
		p.Err = fmt.Errorf("metadata name %q is not valid, must be %q", name, p.Name)
		return p
	}
	if err := p.Metadata.Validate(); err != nil {
		p.Err = fmt.Errorf("invalid metadata: %w", err)
		return p
	}
	return p
}

func addExeSuffix(s string) string {
	if runtime.GOOS == "windows" {
		s += ".exe"
	}
	return s
}
