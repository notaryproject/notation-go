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
	"io/fs"
	"os"
	"path"

	"github.com/notaryproject/notation-go/dir"
)

// ErrNotCompliant is returned by plugin methods when the response is not
// compliant.
var ErrNotCompliant = errors.New("plugin not compliant")

// ErrNotRegularFile is returned when the plugin file is not an regular file.
var ErrNotRegularFile = errors.New("not regular file")

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
