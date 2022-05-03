package manager

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"

	"github.com/notaryproject/notation-go/plugin"
)

// Plugin represents a potential plugin with all it's metadata.
type Plugin struct {
	plugin.Metadata

	Path string `json:",omitempty"`

	// Err is non-nil if the plugin failed one of the candidate tests.
	Err error `json:",omitempty"`
}

// ErrNotFound is returned by Manager.Get and Manager.Run when the plugin is not found.
var ErrNotFound = errors.New("plugin not found")

// ErrNotCompliant is returned by Manager.Run when the plugin is found but not compliant.
var ErrNotCompliant = errors.New("plugin not compliant")

// commander is defined for mocking purposes.
type commander interface {
	// Output runs the command, passing req to the its stdin.
	// It only returns an error if the binary can't be executed.
	// Returns stdout if success is true, stderr if success is false.
	Output(ctx context.Context, path string, command string, req []byte) (out []byte, success bool, err error)
}

// execCommander implements the commander interface using exec.Command().
type execCommander struct{}

func (c execCommander) Output(ctx context.Context, name string, command string, req []byte) ([]byte, bool, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, command)
	cmd.Stdin = bytes.NewReader(req)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if _, ok := err.(*exec.ExitError); err != nil && !ok {
		return nil, false, err
	}
	if !cmd.ProcessState.Success() {
		return stderr.Bytes(), false, nil
	}
	return stdout.Bytes(), true, nil
}

// rootedFS is io.FS implementation used in NewManager.
// root is the root of the file system tree passed to os.DirFS.
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
func NewManager() *Manager {
	configDir, err := os.UserConfigDir()
	if err != nil {
		// Lets panic for now.
		// Once the config is moved to notation-go we will move this code to
		// the config package as a global initialization.
		panic(err)
	}
	pluginDir := filepath.Join(configDir, "notation", "plugins")
	return &Manager{rootedFS{os.DirFS(pluginDir), pluginDir}, execCommander{}}
}

// Get returns a plugin on the system by its name.
//
// If the plugin is not found, the error is of type ErrNotFound.
// The plugin might be incomplete if p.Err is not nil.
func (mgr *Manager) Get(ctx context.Context, name string) (*Plugin, error) {
	return mgr.newPlugin(ctx, name)
}

// List produces a list of the plugins available on the system.
//
// Some plugins might be incomplete if their Err is not nil.
func (mgr *Manager) List(ctx context.Context) ([]*Plugin, error) {
	var plugins []*Plugin
	fs.WalkDir(mgr.fsys, ".", func(dir string, d fs.DirEntry, _ error) error {
		if dir == "." || !d.IsDir() {
			return nil
		}
		p, err := mgr.newPlugin(ctx, d.Name())
		if err == nil {
			plugins = append(plugins, p)
		}
		return fs.SkipDir
	})
	return plugins, nil
}

// Run executes the specified command against the named plugin and waits for it to complete.
//
// When the returned object is not nil, its type is guaranteed to remain always the same for a given Command.
// The type associated to each Command can be found at Command.NewResponse().
//
// The returned error is nil if:
// - the plugin exists and is valid
// - the plugin supports the capability returned by cmd.Capability()
// - the command runs and exits with a zero exit status
// - the command stdout is a valid json object which can be unmarshal-ed into the object returned by cmd.NewResponse().
//
// If the plugin is not found, the error is of type ErrNotFound.
// If the plugin metadata is not valid or stdout and stderr can't be decoded into a valid response, the error is of type ErrNotCompliant.
// If the command starts but does not complete successfully, the error is of type RequestError wrapping a *exec.ExitError.
// Other error types may be returned for other situations.
func (mgr *Manager) Run(ctx context.Context, name string, cmd plugin.Command, req interface{}) (interface{}, error) {
	p, err := mgr.newPlugin(ctx, name)
	if err != nil {
		return nil, pluginErr(name, err)
	}
	if p.Err != nil {
		return nil, pluginErr(name, withErr(p.Err, ErrNotCompliant))
	}
	var data []byte
	if req != nil {
		data, err = json.Marshal(req)
		if err != nil {
			return nil, pluginErr(name, fmt.Errorf("failed to marshal request object: %w", err))
		}
	}
	resp, err := run(ctx, mgr.cmder, p.Path, cmd, data)
	if err != nil {
		return nil, pluginErr(name, err)
	}
	return resp, nil
}

// newPlugin determines if the given candidate is valid and returns a Plugin.
func (mgr *Manager) newPlugin(ctx context.Context, name string) (*Plugin, error) {
	ok := isCandidate(mgr.fsys, name)
	if !ok {
		return nil, ErrNotFound
	}

	p := &Plugin{Path: binPath(mgr.fsys, name)}
	out, err := run(ctx, mgr.cmder, p.Path, plugin.CommandGetMetadata, nil)
	if err != nil {
		p.Err = fmt.Errorf("failed to fetch metadata: %w", err)
		return p, nil
	}
	p.Metadata = *out.(*plugin.Metadata)
	if p.Name != name {
		p.Err = fmt.Errorf("executable name must be %q instead of %q", addExeSuffix(plugin.Prefix+p.Name), filepath.Base(p.Path))
	} else if err := p.Metadata.Validate(); err != nil {
		p.Err = fmt.Errorf("invalid metadata: %w", err)
	}
	return p, nil
}

// run executes the command and decodes the response.
func run(ctx context.Context, cmder commander, pluginPath string, cmd plugin.Command, req []byte) (interface{}, error) {
	out, ok, err := cmder.Output(ctx, pluginPath, string(cmd), req)
	if err != nil {
		return nil, fmt.Errorf("failed running the plugin: %w", err)
	}
	if !ok {
		var re plugin.RequestError
		err = json.Unmarshal(out, &re)
		if err != nil {
			return nil, withErr(plugin.RequestError{Code: plugin.ErrorCodeGeneric, Err: err}, ErrNotCompliant)
		}
		return nil, re
	}
	resp := cmd.NewResponse()
	err = json.Unmarshal(out, resp)
	if err != nil {
		err = fmt.Errorf("failed to decode json response: %w", err)
		return nil, withErr(err, ErrNotCompliant)
	}
	return resp, nil
}

func pluginErr(name string, err error) error {
	return fmt.Errorf("%s: %w", name, err)
}

// isCandidate checks if the named plugin is a valid candidate.
func isCandidate(fsys fs.FS, name string) bool {
	base := binName(name)
	fi, err := fs.Stat(fsys, path.Join(name, base))
	if err != nil {
		// Ignore any file which we cannot Stat
		// (e.g. due to permissions or anything else).
		return false
	}
	if fi.Mode().Type() != 0 {
		// Ignore non-regular files.
		return false
	}
	return true
}

func binName(name string) string {
	return addExeSuffix(plugin.Prefix + name)
}

func binPath(fsys fs.FS, name string) string {
	base := binName(name)
	if fsys, ok := fsys.(rootedFS); ok {
		return filepath.Join(fsys.root, name, base)
	}
	return filepath.Join(name, base)
}

func addExeSuffix(s string) string {
	if runtime.GOOS == "windows" {
		s += ".exe"
	}
	return s
}

func withErr(err, other error) error {
	return unionError{err: err, other: other}
}

type unionError struct {
	err   error
	other error
}

func (u unionError) Error() string {
	return fmt.Sprintf("%s: %s", u.other, u.err)
}

func (u unionError) Is(target error) bool {
	return errors.Is(u.other, target)
}

func (u unionError) As(target interface{}) bool {
	return errors.As(u.other, target)
}

func (u unionError) Unwrap() error {
	return u.err
}
