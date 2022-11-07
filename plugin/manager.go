package plugin

import (
	"context"
	"errors"
	"io/fs"
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

// Get returns a plugin on the system by its name.
//
// If the plugin is not found, the error is of type os.ErrNotExist.
func (m *CLIManager) Get(ctx context.Context, name string) (Plugin, error) {
	// validate file existence
	pluginPath := path.Join(name, binName(name))
	fi, err := fs.Stat(m.pluginFS, pluginPath)
	if err != nil {
		// Ignore any file which we cannot Stat
		// (e.g. due to permissions or anything else).
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		// Ignore non-regular files.
		return nil, ErrNotRegularFile
	}

	// get path
	path, err := m.pluginFS.SysPath(pluginPath)
	if err != nil {
		return nil, err
	}

	// validate and create plugin
	return NewCLIPlugin(name, path)
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

// NewCLIManager returns CLIManager for named pluginFS.
func NewCLIManager(pluginFS dir.SysFS) *CLIManager {
	return &CLIManager{pluginFS: pluginFS}
}
