package manager

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/internal/mock/mockfs"
	"github.com/notaryproject/notation-go/plugin"
)

type smartTestCommander struct {
	commanderMap map[string]testCommander
}

func (t smartTestCommander) Output(ctx context.Context, path string, command string, req []byte) (out []byte, success bool, err error) {
	path = filepath.ToSlash(path)
	return t.commanderMap[path].Output(ctx, path, command, req)
}

type testCommander struct {
	output  []byte
	success bool
	err     error
}

func (t testCommander) Output(ctx context.Context, path string, command string, req []byte) (out []byte, success bool, err error) {
	return t.output, t.success, t.err
}

var validMetadata = plugin.Metadata{
	Name: "foo", Description: "friendly", Version: "1", URL: "example.com",
	SupportedContractVersions: []string{"1"}, Capabilities: []plugin.Capability{plugin.CapabilitySignatureGenerator},
}

var validMetadataBar = plugin.Metadata{
	Name: "bar", Description: "friendly", Version: "1", URL: "example.com",
	SupportedContractVersions: []string{"1"}, Capabilities: []plugin.Capability{plugin.CapabilitySignatureGenerator},
}

func TestManager_Get_Empty(t *testing.T) {
	mgr := &Manager{mockfs.NewSysFSMock(fstest.MapFS{}, ""), nil}
	got, err := mgr.Get(context.Background(), "foo")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Manager.Get() error = %v, want %v", got, ErrNotFound)
	}
	if got != nil {
		t.Errorf("Manager.Get() = %v, want nil", got)
	}
}

func TestManager_Get_NotFound(t *testing.T) {
	check := func(got *Plugin, err error) {
		t.Helper()
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("Manager.Get() error = %v, want %v", got, ErrNotFound)
		}
		if got != nil {
			t.Errorf("Manager.Get() = %v, want nil", got)
		}
	}
	ctx := context.Background()

	// empty fsys.
	mgr := &Manager{mockfs.NewSysFSMock(fstest.MapFS{}, ""), nil}
	check(mgr.Get(ctx, "foo"))

	// plugin directory exists without executable.

	mgr = &Manager{mockfs.NewSysFSMock(fstest.MapFS{
		"foo": &fstest.MapFile{Mode: fs.ModeDir},
	}, ""), nil}
	check(mgr.Get(ctx, "foo"))

	// plugin directory exists with symlinked executable.
	mgr = &Manager{mockfs.NewSysFSMock(fstest.MapFS{
		"foo":                            &fstest.MapFile{Mode: fs.ModeDir},
		addExeSuffix("foo/notation-foo"): &fstest.MapFile{Mode: fs.ModeSymlink},
	}, ""), nil}
	check(mgr.Get(ctx, "foo"))

	// valid plugin exists but is not the target.
	mgr = &Manager{mockfs.NewSysFSMock(fstest.MapFS{
		"foo":                            &fstest.MapFile{Mode: fs.ModeDir},
		addExeSuffix("foo/notation-foo"): new(fstest.MapFile),
	}, ""), testCommander{metadataJSON(validMetadata), true, nil}}
	check(mgr.Get(ctx, "baz"))
}

func TestManager_Get(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name string
		mgr  *Manager
		args args
		want *Plugin
		err  string
	}{
		{
			"command error",
			&Manager{mockfs.NewSysFSMock(
				fstest.MapFS{
					"foo":                            &fstest.MapFile{Mode: fs.ModeDir},
					addExeSuffix("foo/notation-foo"): new(fstest.MapFile),
				}, ""),
				testCommander{nil, false, errors.New("failed")}},
			args{"foo"},
			&Plugin{Path: addExeSuffix("foo/notation-foo")},
			"failed to fetch metadata",
		},
		{
			"invalid json",
			&Manager{mockfs.NewSysFSMock(
				fstest.MapFS{
					"foo":                            &fstest.MapFile{Mode: fs.ModeDir},
					addExeSuffix("foo/notation-foo"): new(fstest.MapFile),
				}, ""),
				testCommander{[]byte("content"), true, nil}},
			args{"foo"},
			&Plugin{Path: addExeSuffix("foo/notation-foo")},
			"failed to fetch metadata",
		},
		{
			"invalid metadata name",
			&Manager{mockfs.NewSysFSMock(
				fstest.MapFS{
					"baz":                            &fstest.MapFile{Mode: fs.ModeDir},
					addExeSuffix("baz/notation-baz"): new(fstest.MapFile),
				}, ""),
				testCommander{metadataJSON(validMetadata), true, nil}},
			args{"baz"},
			&Plugin{Metadata: validMetadata, Path: addExeSuffix("baz/notation-baz")},
			"executable name must be",
		},
		{
			"invalid metadata content",
			&Manager{mockfs.NewSysFSMock(
				fstest.MapFS{
					"foo":                            &fstest.MapFile{Mode: fs.ModeDir},
					addExeSuffix("foo/notation-foo"): new(fstest.MapFile),
				}, ""),
				testCommander{metadataJSON(plugin.Metadata{Name: "foo"}), true, nil}},
			args{"foo"},
			&Plugin{Metadata: plugin.Metadata{Name: "foo"}, Path: addExeSuffix("foo/notation-foo")},
			"invalid metadata",
		},
		{
			"valid",
			&Manager{mockfs.NewSysFSMock(
				fstest.MapFS{
					"foo":                            &fstest.MapFile{Mode: fs.ModeDir},
					addExeSuffix("foo/notation-foo"): new(fstest.MapFile),
				}, ""),
				testCommander{metadataJSON(validMetadata), true, nil}},
			args{"foo"},
			&Plugin{Metadata: validMetadata, Path: addExeSuffix("foo/notation-foo")}, "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.mgr.Get(context.Background(), tt.args.name)
			if err != nil {
				t.Fatalf("Manager.Get() error = %v, want nil", err)
			}
			if tt.err != "" {
				if got.Err == nil {
					t.Errorf("Manager.Get() got.Err = nil, want %v", tt.err)
				} else if !strings.Contains(got.Err.Error(), tt.err) {
					t.Errorf("Manager.Get() got.Err = %v, want %v", got.Err, tt.err)
				}
			} else if got.Err != nil {
				t.Errorf("Manager.Get() got.Err = %v, want nil", got.Err)
			}
			if !reflect.DeepEqual(got.Metadata, tt.want.Metadata) {
				t.Errorf("Manager.Get() = %v, want %v", got, tt.want)
			}
		})
	}
}

func metadataJSON(m plugin.Metadata) []byte {
	d, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return d
}

func TestManager_List(t *testing.T) {
	tests := []struct {
		name string
		mgr  *Manager
		want []*Plugin
	}{
		{"empty fsys",
			&Manager{mockfs.NewSysFSMock(fstest.MapFS{}, ""), nil}, nil},
		{"fsys without plugins",
			&Manager{mockfs.NewSysFSMock(fstest.MapFS{"a.go": &fstest.MapFile{}}, ""), nil}, nil},
		{"fsys with plugins but symlinked",
			&Manager{
				mockfs.NewSysFSMock(fstest.MapFS{
					"foo":                            &fstest.MapFile{Mode: fs.ModeDir | fs.ModeSymlink},
					addExeSuffix("foo/notation-foo"): new(fstest.MapFile),
					"baz":                            &fstest.MapFile{Mode: fs.ModeDir},
				}, ""),
				testCommander{metadataJSON(validMetadata), true, nil}}, nil},
		{
			"fsys with some invalid plugins",
			&Manager{
				mockfs.NewSysFSMock(fstest.MapFS{
					"foo":                            &fstest.MapFile{Mode: fs.ModeDir},
					addExeSuffix("foo/notation-foo"): new(fstest.MapFile),
				}, ""),
				testCommander{metadataJSON(validMetadata), true, nil}}, []*Plugin{{Metadata: validMetadata}}},
		{
			"fsys with plugins",
			&Manager{
				mockfs.NewSysFSMock(fstest.MapFS{
					"foo":                            &fstest.MapFile{Mode: fs.ModeDir},
					addExeSuffix("foo/notation-foo"): new(fstest.MapFile),
					"baz":                            &fstest.MapFile{Mode: fs.ModeDir},
				}, ""),
				testCommander{metadataJSON(validMetadata), true, nil}}, []*Plugin{{Metadata: validMetadata}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := tt.mgr.List(context.Background())
			if len(got) != len(tt.want) {
				t.Fatalf("Manager.List() len = %v, want len %v", len(got), len(tt.want))
			}
			for i := 0; i < len(got); i++ {
				if !reflect.DeepEqual(got[i].Metadata, tt.want[i].Metadata) {
					t.Errorf("Manager.List() got %d = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestManager_Runner_Run_NotFound(t *testing.T) {
	mgr := &Manager{mockfs.NewSysFSMock(fstest.MapFS{}, ""), nil}
	_, err := mgr.Runner("foo")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Manager.Runner() error = %v, want %v", err, ErrNotFound)
	}
}

func TestManager_Runner_Run(t *testing.T) {
	var errExec = errors.New("exec failed")
	type args struct {
		name string
		cmd  plugin.Command
	}
	tests := []struct {
		name string
		mgr  *Manager
		args args
		err  error
	}{
		{"exec error", &Manager{
			mockfs.NewSysFSMock(
				fstest.MapFS{
					"foo":                            &fstest.MapFile{Mode: fs.ModeDir},
					addExeSuffix("foo/notation-foo"): new(fstest.MapFile),
				}, ""),
			&testCommander{nil, false, errExec}},
			args{"foo", plugin.CommandGenerateSignature}, errExec,
		},
		{"request error",
			&Manager{
				mockfs.NewSysFSMock(
					fstest.MapFS{
						"foo":                            &fstest.MapFile{Mode: fs.ModeDir},
						addExeSuffix("foo/notation-foo"): new(fstest.MapFile),
					}, ""),
				&testCommander{[]byte("{\"errorCode\": \"ERROR\"}"), false, nil}},
			args{"foo", plugin.CommandGenerateSignature}, plugin.RequestError{Code: plugin.ErrorCodeGeneric},
		},
		{"valid",
			&Manager{
				mockfs.NewSysFSMock(
					fstest.MapFS{
						"foo":                            &fstest.MapFile{Mode: fs.ModeDir},
						addExeSuffix("foo/notation-foo"): new(fstest.MapFile),
					}, ""),
				&testCommander{metadataJSON(validMetadata), true, nil}},
			args{"foo", plugin.CommandGenerateSignature}, nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner, err := tt.mgr.Runner(tt.args.name)
			if err != nil {
				t.Fatalf("Manager.Runner() error = %v, want nil", err)
			}
			got, err := runner.Run(context.Background(), requester(tt.args.cmd))
			wantErr := tt.err != nil
			if (err != nil) != wantErr {
				t.Fatalf("Runner.Run() error = %v, wantErr %v", err, wantErr)
			}
			if wantErr {
				if !errors.Is(err, tt.err) {
					t.Fatalf("Runner.Run() error = %v, want %v", err, tt.err)
				}
			} else if got == nil {
				t.Error("Runner.Run() want non-nil output")
			}
		})
	}
}

type requester plugin.Command

func (r requester) Command() plugin.Command {
	return plugin.Command(r)
}

func TestNew(t *testing.T) {
	mgr := New(dir.PluginFS())
	if mgr == nil {
		t.Error("New() = nil")
	}
}
