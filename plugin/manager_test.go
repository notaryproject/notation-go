package plugin

import (
	"context"
	"encoding/json"
	"io/fs"
	"reflect"
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

func (t testCommander) Output(ctx context.Context, path string, command proto.Command, req []byte) ([]byte, []byte, error) {
	return t.stdout, t.stderr, t.err
}

var validMetadata = proto.GetMetadataResponse{
	Name: "foo", Description: "friendly", Version: "1", URL: "example.com",
	SupportedContractVersions: []string{"1.0"}, Capabilities: []proto.Capability{proto.CapabilitySignatureGenerator},
}

var invalidMetadataName = proto.GetMetadataResponse{
	Name: "foobar", Description: "friendly", Version: "1", URL: "example.com",
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

func TestManager_Get(t *testing.T) {
	executor = testCommander{stdout: metadataJSON(validMetadata)}
	mgr := NewCLIManager(mockfs.NewSysFSWithRootMock(fstest.MapFS{}, "./testdata/plugins"))
	_, err := mgr.Get(context.Background(), "foo")
	if err != nil {
		t.Errorf("Manager.Get() err %v, want nil", err)
	}
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
