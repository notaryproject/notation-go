package manager

import (
	"encoding/json"
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/notaryproject/notation-go/plugin"
)

type testCommander struct {
	output []byte
	err    error
}

func (t testCommander) Output(string, ...string) ([]byte, error) {
	return t.output, t.err
}

var validMetadata = plugin.Metadata{
	Name: "foo", Description: "friendly", Version: "1", URL: "example.com",
	SupportedContractVersions: []string{"1"}, Capabilities: []string{"cap"},
}

func TestManager_Get(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		mgr     *Manager
		args    args
		want    *Plugin
		err     string
		invalid string
	}{
		{"empty fsys", &Manager{fstest.MapFS{}, nil}, args{"foo"}, nil, "plugin not found", ""},
		{
			"plugin not found",
			&Manager{fstest.MapFS{
				"baz": &fstest.MapFile{Mode: fs.ModeDir},
			}, nil},
			args{"foo"},
			nil, "plugin not found", "",
		},
		{
			"plugin executable does not exists",
			&Manager{fstest.MapFS{
				"foo": &fstest.MapFile{Mode: fs.ModeDir},
			}, nil},
			args{"foo"},
			nil, "plugin not found", "",
		},
		{
			"plugin executable invalid mode",
			&Manager{fstest.MapFS{
				"foo":                            &fstest.MapFile{Mode: fs.ModeDir},
				addExeSuffix("foo/notation-foo"): &fstest.MapFile{Mode: fs.ModeDir},
			}, testCommander{[]byte("content"), nil}},
			args{"foo"},
			nil, "plugin not found", "",
		},
		{
			"discover error",
			&Manager{fstest.MapFS{
				"foo":                            &fstest.MapFile{Mode: fs.ModeDir},
				addExeSuffix("foo/notation-foo"): new(fstest.MapFile),
			}, testCommander{nil, errors.New("failed")}},
			args{"foo"},
			&Plugin{Path: addExeSuffix("foo/notation-foo")},
			"", "failed to fetch metadata",
		},
		{
			"invalid json",
			&Manager{fstest.MapFS{
				"foo":                            &fstest.MapFile{Mode: fs.ModeDir},
				addExeSuffix("foo/notation-foo"): new(fstest.MapFile),
			}, testCommander{[]byte("content"), nil}},
			args{"foo"},
			&Plugin{Path: addExeSuffix("foo/notation-foo")},
			"", "metadata can't be decoded",
		},
		{
			"invalid metadata name",
			&Manager{fstest.MapFS{
				"baz":                            &fstest.MapFile{Mode: fs.ModeDir},
				addExeSuffix("baz/notation-baz"): new(fstest.MapFile),
			}, testCommander{metadataJSON(validMetadata), nil}},
			args{"baz"},
			&Plugin{Metadata: plugin.Metadata{Name: "baz"}, Path: addExeSuffix("baz/notation-baz")},
			"", "executable name must be",
		},
		{
			"invalid metadata content",
			&Manager{fstest.MapFS{
				"foo":                            &fstest.MapFile{Mode: fs.ModeDir},
				addExeSuffix("foo/notation-foo"): new(fstest.MapFile),
			}, testCommander{metadataJSON(plugin.Metadata{Name: "foo"}), nil}},
			args{"foo"},
			&Plugin{Metadata: plugin.Metadata{Name: "foo"}, Path: addExeSuffix("foo/notation-foo")},
			"", "invalid metadata",
		},
		{
			"valid",
			&Manager{fstest.MapFS{
				"foo":                            &fstest.MapFile{Mode: fs.ModeDir},
				addExeSuffix("foo/notation-foo"): new(fstest.MapFile),
			}, testCommander{metadataJSON(validMetadata), nil}},
			args{"foo"},
			&Plugin{Metadata: validMetadata, Path: addExeSuffix("foo/notation-foo")}, "", "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.mgr.Get(tt.args.name)
			if tt.err != "" {
				if err == nil {
					t.Fatalf("Manager.Get() error = nil, want %s", tt.err)
				}
				if !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("Manager.Get() error = %v, want %v", err, tt.err)
				}
			} else if tt.invalid != "" {
				if err != nil {
					t.Fatalf("Manager.Get() error = %v, want nil", err)
				}
				if !strings.Contains(got.Err.Error(), tt.invalid) {
					t.Fatalf("Manager.Get() error = %v, want %v", got.Err, tt.invalid)
				}
			} else {
				if err != nil {
					t.Fatalf("Manager.Get() error = %v, want nil", err)
				}
				if got.Err != nil {
					t.Fatalf("Manager.Get() error = %v, want nil", got.Err)
				}
				if !reflect.DeepEqual(got.Metadata, tt.want.Metadata) {
					t.Errorf("Manager.Get() = %v, want %v", got, tt.want)
				}
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
		{"empty fsys", &Manager{fstest.MapFS{}, nil}, nil},
		{"fsys without plugins", &Manager{fstest.MapFS{"a.go": &fstest.MapFile{}}, nil}, nil},
		{
			"fsys with some invalid plugins", &Manager{
				fstest.MapFS{
					"foo":                            &fstest.MapFile{Mode: fs.ModeDir},
					addExeSuffix("foo/notation-foo"): new(fstest.MapFile),
				}, testCommander{metadataJSON(validMetadata), nil}},
			[]*Plugin{{Metadata: validMetadata}},
		},
		{
			"fsys with plugins", &Manager{
				fstest.MapFS{
					"foo":                            &fstest.MapFile{Mode: fs.ModeDir},
					addExeSuffix("foo/notation-foo"): new(fstest.MapFile),
					"baz":                            &fstest.MapFile{Mode: fs.ModeDir},
				}, testCommander{metadataJSON(validMetadata), nil}},
			[]*Plugin{{Metadata: validMetadata}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := tt.mgr.List()
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

func TestManager_Command(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		mgr     *Manager
		args    args
		wantErr bool
	}{
		{"empty fsys", &Manager{fstest.MapFS{}, nil}, args{"foo"}, true},
		{
			"invalid plugin", &Manager{fstest.MapFS{
				"foo":                            &fstest.MapFile{Mode: fs.ModeDir},
				addExeSuffix("foo/notation-foo"): new(fstest.MapFile),
			}, testCommander{nil, errors.New("err")}},
			args{"foo"}, true,
		},
		{
			"valid", &Manager{fstest.MapFS{
				"foo":                            &fstest.MapFile{Mode: fs.ModeDir},
				addExeSuffix("foo/notation-foo"): new(fstest.MapFile),
			}, testCommander{metadataJSON(validMetadata), nil}},
			args{"foo"}, false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.mgr.Command(tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("Manager.Command() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == nil {
				t.Error("Manager.Command() want non-nil cmd")
			}
		})
	}
}
