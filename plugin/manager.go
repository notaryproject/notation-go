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
	"github.com/notaryproject/notation-go/log"
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
	// It may contain extra lib files and LICENSE files.
	// On success, these files will be installed as well.
	//
	// 2. A single plugin executable file following the spec.
	PluginPath string

	// Overwrite is a boolean flag. When set, always install the new plugin.
	Overwrite bool
}

// Install installs a plugin to the system. It returns existing
// plugin metadata, new plugin metadata, and error. It returns nil error
// if and only if the installation succeeded.
//
// If plugin does not exist, directly install the new plugin.
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
		return nil, nil, errors.New("plugin source path cannot be empty")
	}
	var installFromNonDir bool
	pluginExecutableFile, pluginName, err := parsePluginFromDir(ctx, installOpts.PluginPath)
	if err != nil {
		if !errors.Is(err, file.ErrNotDirectory) {
			return nil, nil, fmt.Errorf("failed to read plugin from input directory: %w", err)
		}
		// input is not a dir, check if it's a single plugin executable file
		installFromNonDir = true
		pluginExecutableFile = installOpts.PluginPath
		pluginName, err = parsePluginName(filepath.Base(pluginExecutableFile))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read plugin name from input file: %w", err)
		}
		isExec, err := isExecutableFile(pluginExecutableFile)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to check if input file is executable: %w", err)
		}
		if !isExec {
			return nil, nil, errors.New("input file is not executable")
		}
	}
	// validate and get new plugin metadata
	newPlugin, err := NewCLIPlugin(ctx, pluginName, pluginExecutableFile)
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
		// fail only if overwrite is not set
		if !errors.Is(err, os.ErrNotExist) && !overwrite {
			return nil, nil, fmt.Errorf("failed to check plugin existence: %w", err)
		}
	} else { // plugin already exists
		existingPluginMetadata, err = existingPlugin.GetMetadata(ctx, &proto.GetMetadataRequest{})
		if err != nil && !overwrite { // fail only if overwrite is not set
			return nil, nil, fmt.Errorf("failed to get metadata of existing plugin: %w", err)
		}
		// existing plugin is valid, and overwrite is not set, check version
		if !overwrite {
			comp, err := semver.ComparePluginVersion(newPluginMetadata.Version, existingPluginMetadata.Version)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to compare plugin versions: %w", err)
			}
			switch {
			case comp < 0:
				return nil, nil, PluginDowngradeError{Msg: fmt.Sprintf("failed to install plugin %s. The installing plugin version %s is lower than the existing plugin version %s", pluginName, newPluginMetadata.Version, existingPluginMetadata.Version)}
			case comp == 0:
				return nil, nil, InstallEqualVersionError{Msg: fmt.Sprintf("plugin %s with version %s already exists", pluginName, existingPluginMetadata.Version)}
			}
		}
	}
	// clean up before installation, this guarantees idempotent for install
	if err := m.Uninstall(ctx, pluginName); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("failed to clean up plugin %s before installation: %w", pluginName, err)
		}
	}
	// core process
	pluginDirPath, err := m.pluginFS.SysPath(pluginName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get the system path of plugin %s: %w", pluginName, err)
	}
	if installFromNonDir {
		if err := file.CopyToDir(pluginExecutableFile, pluginDirPath); err != nil {
			return nil, nil, fmt.Errorf("failed to copy plugin executable file from %s to %s: %w", pluginExecutableFile, pluginDirPath, err)
		}
	} else {
		if err := file.CopyDirToDir(installOpts.PluginPath, pluginDirPath); err != nil {
			return nil, nil, fmt.Errorf("failed to copy plugin files from %s to %s: %w", installOpts.PluginPath, pluginDirPath, err)
		}
	}
	return existingPluginMetadata, newPluginMetadata, nil
}

// Uninstall uninstalls a plugin on the system by its name.
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
// one and only one plugin executable file candidate.
// The dir may contain extra lib files and LICENSE files.
// Sub-directories are ignored.
//
// On success, the plugin executable file path, plugin name and
// nil error are returned.
func parsePluginFromDir(ctx context.Context, path string) (string, string, error) {
	// sanity check
	fi, err := os.Stat(path)
	if err != nil {
		return "", "", err
	}
	if !fi.Mode().IsDir() {
		return "", "", file.ErrNotDirectory
	}
	logger := log.GetLogger(ctx)
	// walk the path
	var pluginExecutableFile, pluginName, candidatePluginName string
	var foundPluginExecutableFile bool
	var filesWithValidNameFormat []string
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
		// only take regular files
		if info.Mode().IsRegular() {
			if candidatePluginName, err = parsePluginName(d.Name()); err != nil {
				// file name does not follow the notation-{plugin-name} format,
				// continue
				return nil
			}
			filesWithValidNameFormat = append(filesWithValidNameFormat, p)
			isExec, err := isExecutableFile(p)
			if err != nil {
				return err
			}
			if !isExec {
				return nil
			}
			if foundPluginExecutableFile {
				return errors.New("found more than one plugin executable files")
			}
			foundPluginExecutableFile = true
			pluginExecutableFile = p
			pluginName = candidatePluginName
		}
		return nil
	}); err != nil {
		return "", "", err
	}
	if !foundPluginExecutableFile {
		// if no executable file was found, but there's one and only one
		// potential candidate, try install the candidate
		if len(filesWithValidNameFormat) == 1 {
			candidate := filesWithValidNameFormat[0]
			if err := setExecutable(candidate); err != nil {
				return "", "", fmt.Errorf("no plugin executable file was found: %w", err)
			}
			logger.Warnf("Found candidate plugin executable file %q without executable permission. Setting user executable bit and trying to install.", filepath.Base(candidate))
			return candidate, candidatePluginName, nil
		}
		return "", "", errors.New("no plugin executable file was found")
	}
	return pluginExecutableFile, pluginName, nil
}
