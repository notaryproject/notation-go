package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/notaryproject/notation-go/internal/mock/mockfs"
	"github.com/notaryproject/notation-go/plugin/proto"
)

type testCommander struct {
	stdout []byte
	stderr []byte
	err    error
}

func (t testCommander) Output(ctx context.Context, path string, command proto.Command, req []byte) (stdout []byte, stderr []byte, err error) {
	return t.stdout, t.stderr, t.err
}

var validMetadata = proto.GetMetadataResponse{
	Name: "foo", Description: "friendly", Version: "1", URL: "example.com",
	SupportedContractVersions: []string{"1.0"}, Capabilities: []proto.Capability{proto.CapabilitySignatureGenerator},
}

var validMetadataBar = proto.GetMetadataResponse{
	Name: "bar", Description: "friendly", Version: "1", URL: "example.com",
	SupportedContractVersions: []string{"1"}, Capabilities: []proto.Capability{proto.CapabilitySignatureGenerator},
}

var invalidContractVersionMetadata = proto.GetMetadataResponse{
	Name: "foo", Description: "friendly", Version: "1", URL: "example.com",
	SupportedContractVersions: []string{"110.0"}, Capabilities: []proto.Capability{proto.CapabilitySignatureGenerator},
}

func TestManager_Get_Empty(t *testing.T) {
	mgr := NewCLIManager(mockfs.NewSysFSMock(fstest.MapFS{}))
	got, err := mgr.Get(context.Background(), "foo", nil)
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Manager.Get() error = %v, want %v", err, os.ErrNotExist)
	}
	if got != nil {
		t.Errorf("Manager.Get() = %v, want nil", got)
	}
}

func TestManager_Get_NotFound(t *testing.T) {
	check := func(got Plugin, err error) {
		t.Helper()
		if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("Manager.Get() error = %v, want %v", err, os.ErrNotExist)
		}
		if got != nil {
			t.Errorf("Manager.Get() = %v, want nil", got)
		}
	}
	ctx := context.Background()

	// empty fsys.
	mgr := NewCLIManager(mockfs.NewSysFSMock(fstest.MapFS{}))
	check(mgr.Get(ctx, "foo", nil))

	// plugin directory exists without executable.
	mgr = NewCLIManager(mockfs.NewSysFSMock(fstest.MapFS{
		"foo": &fstest.MapFile{Mode: fs.ModeDir},
	}))
	check(mgr.Get(ctx, "foo", nil))

	// plugin directory exists with symlinked executable.
	mgr = NewCLIManager(mockfs.NewSysFSMock(fstest.MapFS{
		"foo":                   &fstest.MapFile{Mode: fs.ModeDir},
		"foo/" + binName("foo"): &fstest.MapFile{Mode: fs.ModeSymlink},
	}))
	got, err := mgr.Get(ctx, "foo", nil)
	if !errors.Is(err, ErrNotRegularFile) {
		t.Errorf("Manager.Get() error = %v, want %v", err, ErrNotRegularFile)
	}
	if got != nil {
		t.Errorf("Manager.Get() = %v, want nil", got)
	}
	// valid plugin exists but is not the target.
	mgr = NewCLIManager(mockfs.NewSysFSMock(fstest.MapFS{
		"foo":                   &fstest.MapFile{Mode: fs.ModeDir},
		"foo/" + binName("foo"): new(fstest.MapFile),
	}))
	executor = testCommander{stdout: metadataJSON(validMetadata)}
	check(mgr.Get(ctx, "baz", nil))
}

func TestManager_Get(t *testing.T) {
	t.Run("command error", func(t *testing.T) {
		mgr := NewCLIManager(mockfs.NewSysFSMock(
			fstest.MapFS{
				"foo":                   &fstest.MapFile{Mode: fs.ModeDir},
				"foo/" + binName("foo"): new(fstest.MapFile),
			}))
		executor = testCommander{}
		_, err := mgr.Get(context.Background(), "foo", nil)
		if !strings.Contains(err.Error(), "failed to fetch metadata") {
			t.Fatal("should fail the Get operation.")
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		mgr := NewCLIManager(mockfs.NewSysFSMock(
			fstest.MapFS{
				"foo":                   &fstest.MapFile{Mode: fs.ModeDir},
				"foo/" + binName("foo"): new(fstest.MapFile),
			}))
		executor = testCommander{stdout: []byte("content")}
		_, err := mgr.Get(context.Background(), "foo", nil)
		if !strings.Contains(err.Error(), "failed to fetch metadata") {
			t.Fatal("should fail the Get operation.")
		}
	})

	t.Run("invalid metadata name", func(t *testing.T) {
		mgr := NewCLIManager(mockfs.NewSysFSMock(
			fstest.MapFS{
				"baz":                   &fstest.MapFile{Mode: fs.ModeDir},
				"baz/" + binName("baz"): new(fstest.MapFile),
			}))
		executor = testCommander{stdout: metadataJSON(validMetadata)}
		_, err := mgr.Get(context.Background(), "baz", nil)
		if !strings.Contains(err.Error(), "executable name must be") {
			t.Fatal("should fail the Get operation.")
		}
	})

	t.Run("invalid metadata content", func(t *testing.T) {
		mgr := NewCLIManager(mockfs.NewSysFSMock(
			fstest.MapFS{
				"foo":                   &fstest.MapFile{Mode: fs.ModeDir},
				"foo/" + binName("foo"): new(fstest.MapFile),
			}))
		executor = testCommander{stdout: metadataJSON(proto.GetMetadataResponse{Name: "foo"})}
		_, err := mgr.Get(context.Background(), "foo", nil)
		if !strings.Contains(err.Error(), "invalid metadata") {
			t.Fatal("should fail the Get operation.")
		}
	})

	t.Run("valid", func(t *testing.T) {
		mgr := NewCLIManager(mockfs.NewSysFSMock(
			fstest.MapFS{
				"foo":                   &fstest.MapFile{Mode: fs.ModeDir},
				"foo/" + binName("foo"): new(fstest.MapFile),
			}))
		executor = testCommander{stdout: metadataJSON(validMetadata)}
		plugin, err := mgr.Get(context.Background(), "foo", nil)
		if err != nil {
			t.Fatalf("should valid. got err = %v", err)
		}
		metadata, err := plugin.GetMetadata(context.Background(), &proto.GetMetadataRequest{})
		if err != nil {
			t.Fatalf("should valid. got err = %v", err)
		}
		if !reflect.DeepEqual(metadata, &validMetadata) {
			t.Fatalf("should be equal. got metadata = %+v, want %+v", metadata, validMetadata)
		}
	})

	t.Run("invalid contract version", func(t *testing.T) {
		mgr := NewCLIManager(mockfs.NewSysFSMock(
			fstest.MapFS{
				"foo":                   &fstest.MapFile{Mode: fs.ModeDir},
				"foo/" + binName("foo"): new(fstest.MapFile),
			}))
		executor = testCommander{stdout: metadataJSON(invalidContractVersionMetadata)}
		_, err := mgr.Get(context.Background(), "foo", nil)
		if err == nil {
			t.Fatal("should have an invalid contract version error")
		}
	})
}

func TestManager_List(t *testing.T) {
	t.Run("empty fsys", func(t *testing.T) {
		mgr := NewCLIManager(mockfs.NewSysFSMock(fstest.MapFS{}))
		plugins, err := mgr.List(context.Background())
		if err != nil {
			t.Fatalf("should no error. got err = %v", err)
		}
		if len(plugins) != 0 {
			t.Fatalf("should no plugins. got plugins = %v", plugins)
		}
	})

	t.Run("fsys with plugins", func(t *testing.T) {
		mgr := NewCLIManager(mockfs.NewSysFSMock(fstest.MapFS{
			"foo": &fstest.MapFile{Mode: fs.ModeDir},
			"baz": &fstest.MapFile{Mode: fs.ModeDir},
		}))
		plugins, err := mgr.List(context.Background())
		if err != nil {
			t.Fatalf("should no error. got err = %v", err)
		}
		want := []string{"foo", "bar"}
		if reflect.DeepEqual(want, plugins) {
			t.Fatalf("got plugins = %v, want %v", plugins, want)
		}
	})
}

func metadataJSON(m proto.GetMetadataResponse) []byte {
	d, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return d
}
