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

// CLIInstallOptions provides user customized options for plugin installation
type CLIInstallOptions struct {
	// PluginPath can be path of:
	//
	// 1. A directory which contains plugin related files. Sub-directories are
	// ignored. It MUST contain one and only one valid plugin executable file
	// following spec: https://github.com/notaryproject/specifications/blob/v1.0.0/specs/plugin-extensibility.md#installation
	//
	// 2. A single valid plugin executalbe file.
	PluginPath string

	// Overwrite is a boolean flag. When set, always install the new plugin.
	Overwrite bool
}

// Install installs a plugin to the system. It returns existing
// plugin metadata, new plugin metadata, and error. It returns nil error
// if and only if the installation succeeded.
//
// If plugin does not exist, directly install from PluginPath.
//
// If plugin already exists:
//
// If overwrite is not set, then the new plugin
// version MUST be higher than the existing plugin version.
//
// If overwrite is set, version check is skipped. If existing
// plugin is malfunctioning, it will be overwritten.
func (m *CLIManager) Install(ctx context.Context, installOpts CLIInstallOptions) (*proto.GetMetadataResponse, *proto.GetMetadataResponse, error) {
	// initialization
	overwrite := installOpts.Overwrite
	if installOpts.PluginPath == "" {
		return nil, nil, errors.New("plugin path cannot be empty")
	}
	var installFromSingleFile bool
	var pluginFile, pluginName string
	pluginFile, pluginName, err := parsePluginFromDir(installOpts.PluginPath)
	if err != nil {
		if !errors.Is(err, file.ErrNotDirectory) {
			return nil, nil, fmt.Errorf("failed to validate plugin directory: %w", err)
		}
		// input is not a dir
		installFromSingleFile = true
		pluginFile = installOpts.PluginPath
		pluginName, err = ParsePluginName(filepath.Base(pluginFile))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get plugin name from file path: %w", err)
		}
	}
	// validate and get new plugin metadata
	if err := validatePluginFileExtensionAgainstOS(filepath.Base(pluginFile), pluginName); err != nil {
		return nil, nil, err
	}
	newPlugin, err := NewCLIPlugin(ctx, pluginName, pluginFile)
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
			return nil, nil, fmt.Errorf("failed to check plugin existence: %w", err)
		}
	} else { // plugin already exists
		var err error
		existingPluginMetadata, err = existingPlugin.GetMetadata(ctx, &proto.GetMetadataRequest{})
		if err != nil && !overwrite { // fail only if overwrite is not set
			return nil, nil, fmt.Errorf("failed to get metadata of existing plugin: %w", err)
		}
		if !overwrite { // err is nil, and overwrite is not set, check version
			comp, err := semver.ComparePluginVersion(newPluginMetadata.Version, existingPluginMetadata.Version)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to compare plugin versions: %w", err)
			}
			switch {
			case comp < 0:
				return nil, nil, PluginDowngradeError{Msg: fmt.Sprintf("the installing plugin version %s is lower than the existing plugin version %s", newPluginMetadata.Version, existingPluginMetadata.Version)}
			case comp == 0:
				return nil, nil, InstallEqualVersionError{Msg: fmt.Sprintf("plugin %s with version %s already exists", pluginName, existingPluginMetadata.Version)}
			}
		}
	}
	pluginDirPath, err := m.pluginFS.SysPath(pluginName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get the system path of plugin %s: %w", pluginName, err)
	}
	if installFromSingleFile {
		if err := file.CopyToDir(pluginFile, pluginDirPath); err != nil {
			return nil, nil, fmt.Errorf("failed to copy plugin executable file from %s to %s: %w", pluginFile, pluginDirPath, err)
		}
	} else {
		if err := file.CopyDirToDir(installOpts.PluginPath, pluginDirPath); err != nil {
			return nil, nil, fmt.Errorf("failed to copy plugin files from %s to %s: %w", installOpts.PluginPath, pluginDirPath, err)
		}
	}
	// plugin binary file is always executable
	pluginFilePath := path.Join(pluginDirPath, filepath.Base(pluginFile))
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

// parsePluginFromDir checks if a dir is a valid plugin dir which contains
// one and only one valid plugin executable file. Sub-directories are ignored.
//
// On success, the plugin executable file path, plugin name and
// nil error are returned.
func parsePluginFromDir(path string) (string, string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", "", err
	}
	if !fi.Mode().IsDir() {
		return "", "", file.ErrNotDirectory
	}
	// walk the path
	var pluginExecutableFile string
	var pluginName string
	var foundPluginExecutableFile bool
	if err := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// skip sub-directories
		if d.IsDir() && d.Name() != filepath.Base(path) {
			return fs.SkipDir
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			if pluginName, err = ParsePluginName(d.Name()); err != nil {
				// file name does not follow the notation-{plugin-name} format
				return nil
			}
			isExec, err := isExecutableFile(p)
			if err != nil {
				return err
			}
			if isExec {
				if foundPluginExecutableFile {
					return fmt.Errorf("found more than one valid plugin executable files under %s", path)
				}
				foundPluginExecutableFile = true
				pluginExecutableFile = p
			}
		}
		return nil
	}); err != nil {
		return "", "", err
	}
	if !foundPluginExecutableFile {
		return "", "", fmt.Errorf("no valid plugin executable file was found under %s", path)
	}
	return pluginExecutableFile, pluginName, nil
}
