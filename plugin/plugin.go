package plugin

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
)

const (
	// NamePrefix is the prefix required on all plugin binary names.
	NamePrefix = "notation-"

	// MetadataSubcommandName is the name of the plugin subcommand
	// which must be supported by every plugin and returns the
	// plugin metadata.
	MetadataSubcommandName = "get-plugin-metadata"
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

	meta, err := cmder.Output(p.Path, MetadataSubcommandName)
	if err != nil {
		p.Err = fmt.Errorf("failed to fetch metadata: %w", err)
		return p
	}

	if err := json.Unmarshal(meta, &p.Metadata); err != nil {
		p.Err = fmt.Errorf("metadata can't be decoded: %w", err)
		return p
	}
	if p.Name != name {
		p.Err = fmt.Errorf("executable name must be %q instead of %q", addExeSuffix(NamePrefix+p.Name), filepath.Base(binPath))
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
