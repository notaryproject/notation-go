package manager

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"

	"github.com/notaryproject/notation-go/dir"
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

// Manager manages plugins installed on the system.
type Manager struct {
	fsys  dir.SysFS
	cmder commander
}

// New returns a new manager.
func New(fsys dir.SysFS) *Manager {
	return &Manager{fsys, execCommander{}}
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
		if dir == "." {
			// Ignore root dir.
			return nil
		}
		typ := d.Type()
		if !typ.IsDir() || typ&fs.ModeSymlink != 0 {
			// Ignore non-directories and symlinked directories.
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

// Runner returns a plugin.Runner.
//
// If the plugin is not found or is not a valid candidate, the error is of type ErrNotFound.
func (mgr *Manager) Runner(name string) (plugin.Runner, error) {
	ok := isCandidate(mgr.fsys, name)
	if !ok {
		return nil, ErrNotFound
	}

	return pluginRunner{name: name, path: binPath(mgr.fsys, name), cmder: mgr.cmder}, nil
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

type pluginRunner struct {
	name  string
	path  string
	cmder commander
}

func (p pluginRunner) Run(ctx context.Context, req plugin.Request) (interface{}, error) {
	var data []byte
	if req != nil {
		var err error
		data, err = json.Marshal(req)
		if err != nil {
			return nil, pluginErr(p.name, fmt.Errorf("failed to marshal request object: %w", err))
		}
	}
	resp, err := run(ctx, p.cmder, p.path, req.Command(), data)
	if err != nil {
		return nil, pluginErr(p.name, err)
	}
	return resp, nil
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
			return nil, plugin.RequestError{Code: plugin.ErrorCodeGeneric, Err: fmt.Errorf("failed to decode json response: %w", ErrNotCompliant)}
		}
		return nil, re
	}
	var resp interface{}
	switch cmd {
	case plugin.CommandGetMetadata:
		resp = new(plugin.Metadata)
	case plugin.CommandGenerateSignature:
		resp = new(plugin.GenerateSignatureResponse)
	case plugin.CommandGenerateEnvelope:
		resp = new(plugin.GenerateEnvelopeResponse)
	case plugin.CommandDescribeKey:
		resp = new(plugin.DescribeKeyResponse)
	case plugin.CommandVerifySignature:
		resp = new(plugin.VerifySignatureResponse)
	default:
		return nil, fmt.Errorf("unsupported command: %s", cmd)
	}
	err = json.Unmarshal(out, resp)
	if err != nil {
		return nil, fmt.Errorf("failed to decode json response: %w", ErrNotCompliant)
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
	if !fi.Mode().IsRegular() {
		// Ignore non-regular files.
		return false
	}
	return true
}

func binName(name string) string {
	return addExeSuffix(plugin.Prefix + name)
}

func binPath(fsys dir.SysFS, name string) string {
	base := binName(name)
	if path, err := fsys.SysPath(name, base); err == nil {
		return path
	}
	return filepath.Join(name, base)
}

func addExeSuffix(s string) string {
	if runtime.GOOS == "windows" {
		s += ".exe"
	}
	return s
}
