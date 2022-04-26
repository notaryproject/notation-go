package plugin

import (
	"io/fs"
	"os"
	"os/exec"
	"path"
)

// commander is defined for mocking purposes.
type commander interface {
	Output(string, ...string) ([]byte, error)
}

type rootedCommander struct {
	root string
}

func (c rootedCommander) Output(name string, args ...string) ([]byte, error) {
	cmd := &exec.Cmd{
		Path: path.Join(c.root, name),
		Args: append([]string{path.Base(name)}, args...),
	}
	return cmd.Output()
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
	return &Manager{os.DirFS(pluginDir), rootedCommander{pluginDir}}, nil
}

// Get returns a plugin on the system by its name.
// The plugin might be incomplete if p.Err is not nil.
func (mgr *Manager) Get(name string) (*Plugin, error) {
	fullname, ok := mgr.isCandidate(name)
	if !ok {
		return nil, ErrNotFound
	}
	p := newPlugin(mgr.cmder, fullname, name)
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

func (mgr *Manager) isCandidate(name string) (fullname string, ok bool) {
	fullname = path.Join(name, "notation-"+name)
	fi, err := fs.Stat(mgr.fsys, addExeSuffix(fullname))
	if err != nil {
		// Ignore any file which we cannot Stat
		// (e.g. due to permissions or anything else).
		return "", false
	}
	if fi.Mode().Type() == 0 {
		// Regular file, keep going.
		return fullname, true
	}
	// Something else, ignore.
	return "", false
}
