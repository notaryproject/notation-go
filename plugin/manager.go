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

package plugin

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/internal/file"
	"github.com/notaryproject/notation-go/internal/semver"
	"github.com/notaryproject/notation-go/plugin/proto"
)

// ErrNotCompliant is returned by plugin methods when the response is not
// compliant.
var ErrNotCompliant = errors.New("plugin not compliant")

// ErrNotRegularFile is returned when the plugin file is not an regular file.
var ErrNotRegularFile = errors.New("not regular file")

// ErrInstallLowerVersion is returned when installing a plugin with version
// lower than the exisiting plugin version.
var ErrInstallLowerVersion = errors.New("installing plugin with version lower than the existing plugin version")

// ErrInstallEqualVersion is returned when installing a plugin with version
// equal to the exisiting plugin version.
var ErrInstallEqualVersion = errors.New("installing plugin with version equal to the existing plugin version")

// Manager manages plugins installed on the system.
type Manager interface {
	Get(ctx context.Context, name string) (Plugin, error)
	List(ctx context.Context) ([]string, error)
}

// CLIManager implements Manager
type CLIManager struct {
	pluginFS dir.SysFS
}

// NewCLIManager returns CLIManager for named pluginFS.
func NewCLIManager(pluginFS dir.SysFS) *CLIManager {
	return &CLIManager{pluginFS: pluginFS}
}

// Get returns a plugin on the system by its name.
//
// If the plugin is not found, the error is of type os.ErrNotExist.
func (m *CLIManager) Get(ctx context.Context, name string) (Plugin, error) {
	pluginPath := path.Join(name, binName(name))
	path, err := m.pluginFS.SysPath(pluginPath)
	if err != nil {
		return nil, err
	}

	// validate and create plugin
	return NewCLIPlugin(ctx, name, path)
}

// List produces a list of the plugin names on the system.
func (m *CLIManager) List(ctx context.Context) ([]string, error) {
	var plugins []string
	fs.WalkDir(m.pluginFS, ".", func(dir string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if dir == "." {
			// Ignore root dir.
			return nil
		}
		typ := d.Type()
		if !typ.IsDir() || typ&fs.ModeSymlink != 0 {
			// Ignore non-directories and symlinked directories.
			return nil
		}

		// add plugin name
		plugins = append(plugins, d.Name())
		return fs.SkipDir
	})
	return plugins, nil
}

// Install installs a plugin at filePath to the system.
//
// It returns the new plugin metadata and a nil eror if and only if
// the installation succeeded.
//
// If plugin already exists, and overwrite is not set, then the new plugin
// version MUST be higher than the existing plugin version.
// If overwrite is set, version check is skipped.
// On sucess, existing plugin metadata and new plugin metadata are returned.
//
// If plugin does not exist, directly install the plugin from filePath.
// On success, the new plugin metadata is returned.
func (m *CLIManager) Install(ctx context.Context, filePath string, overwrite bool) (*proto.GetMetadataResponse, *proto.GetMetadataResponse, error) {
	// validate and get new plugin metadata
	pluginName, err := ExtractPluginNameFromFileName(filepath.Base(filePath))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get plugin name from file path: %w", err)
	}
	if err := validatePluginFileExtensionAgainstOS(filePath, pluginName); err != nil {
		return nil, nil, err
	}
	newPlugin, err := NewCLIPlugin(ctx, pluginName, filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create new CLI plugin: %w", err)
	}
	newPluginMetadata, err := newPlugin.GetMetadata(ctx, &proto.GetMetadataRequest{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get metadata of new plugin: %w", err)
	}
	// check plugin existence and get existing plugin metadata
	var existingPluginMetadata *proto.GetMetadataResponse
	existingPlugin, err := m.Get(ctx, pluginName)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("failed to get existing plugin: %w", err)
		}
	} else { // plugin already exists
		var err error
		existingPluginMetadata, err = existingPlugin.GetMetadata(ctx, &proto.GetMetadataRequest{})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get metadata of existing plugin: %w", err)
		}
		if !overwrite { // overwrite is not set, check version
			comp, err := semver.ComparePluginVersion(newPluginMetadata.Version, existingPluginMetadata.Version)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to compare plugin versions: %w", err)
			}
			switch {
			case comp < 0:
				return nil, nil, ErrInstallLowerVersion
			case comp == 0:
				return nil, nil, ErrInstallEqualVersion
			}
		}
	}
	pluginDirPath, err := m.pluginFS.SysPath(pluginName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get the system path of plugin %s: %w", pluginName, err)
	}
	_, err = file.CopyToDir(filePath, pluginDirPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to copy plugin executable file from %s to %s: %w", filePath, pluginDirPath, err)
	}
	// plugin is always executable
	pluginFilePath := path.Join(pluginDirPath, binName(pluginName))
	if err := os.Chmod(pluginFilePath, 0700); err != nil {
		return nil, nil, fmt.Errorf("failed to change the plugin executable file mode: %w", err)
	}
	return existingPluginMetadata, newPluginMetadata, nil
}

// Uninstall uninstalls a plugin on the system by its name
// If the plugin dir does not exist, os.ErrNotExist is returned.
func (m *CLIManager) Uninstall(ctx context.Context, name string) error {
	pluginDirPath, err := m.pluginFS.SysPath(name)
	if err != nil {
		return err
	}
	if _, err := os.Stat(pluginDirPath); err != nil {
		return err
	}
	return os.RemoveAll(pluginDirPath)
}
