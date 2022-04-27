package plugin

import (
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
)

// commander is defined for mocking purposes.
type commander interface {
	Output(string, ...string) ([]byte, error)
}

type execCommander struct {
	root string
}

func (c execCommander) Output(name string, args ...string) ([]byte, error) {
	cmd := &exec.Cmd{
		Path: name,
		Args: append([]string{name}, args...),
	}
	return cmd.Output()
}

type rootedFS struct {
	fs.FS
	root string
}

// Manager manages plugins installed on the system.
type Manager struct {
	fsys  fs.FS
	cmder commander
}

// NewManager returns a new manager.
func NewManager() (*Manager, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	pluginDir := path.Join(homeDir, ".notation", "plugins")
	return &Manager{rootedFS{os.DirFS(pluginDir), pluginDir}, execCommander{}}, nil
}

// Get returns a plugin on the system by its name.
// The plugin might be incomplete if p.Err is not nil.
func (mgr *Manager) Get(name string) (*Plugin, error) {
	binPath, ok := mgr.isCandidate(name)
	if !ok {
		return nil, ErrNotFound
	}
	p := newPlugin(mgr.cmder, binPath, name)
	return p, nil
}

// List produces a list of the plugins available on the system.
// Some plugins might be incomplete if their Err is not nil.
func (mgr *Manager) List() ([]*Plugin, error) {
	var plugins []*Plugin
	fs.WalkDir(mgr.fsys, ".", func(dir string, d fs.DirEntry, _ error) error {
		if dir == "." || !d.IsDir() {
			return nil
		}
		p, err := mgr.Get(d.Name())
		if err == nil {
			plugins = append(plugins, p)
		}
		return fs.SkipDir
	})
	return plugins, nil
}

// Command returns an "os/exec".Cmd which when .Run() will execute the named plugin.
// The error returned is ErrNotFound if no plugin was found.
func (mgr *Manager) Command(name string, args ...string) (*exec.Cmd, error) {
	p, err := mgr.Get(name)
	if err != nil {
		return nil, err
	}
	if p.Err != nil {
		return nil, p.Err
	}
	return exec.Command(p.Path, args...), nil
}

func (mgr *Manager) isCandidate(name string) (string, bool) {
	base := addExeSuffix("notation-" + name)
	fi, err := fs.Stat(mgr.fsys, path.Join(name, base))
	if err != nil {
		// Ignore any file which we cannot Stat
		// (e.g. due to permissions or anything else).
		return "", false
	}
	if fi.Mode().Type() != 0 {
		// Ignore non-regular files.
		return "", false
	}
	if fsys, ok := mgr.fsys.(rootedFS); ok {
		return filepath.Join(fsys.root, name, base), true
	}
	return filepath.Join(name, base), true
}
