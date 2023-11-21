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
	"encoding/json"
	"io/fs"
	"os"
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

func TestManager_Uninstall(t *testing.T) {
	executor = testCommander{stdout: metadataJSON(validMetadata)}
	mgr := NewCLIManager(mockfs.NewSysFSWithRootMock(fstest.MapFS{}, "./testdata/plugins"))
	if err := os.MkdirAll("./testdata/plugins/toUninstall", 0777); err != nil {
		t.Fatalf("failed to create toUninstall dir: %v", err)
	}
	defer os.RemoveAll("./testdata/plugins/toUninstall")
	pluginFile, err := os.Create("./testdata/plugins/toUninstall/toUninstall")
	if err != nil {
		t.Fatalf("failed to create toUninstall file: %v", err)
	}
	if err := pluginFile.Close(); err != nil {
		t.Fatalf("failed to close toUninstall file: %v", err)
	}
	// test uninstall valid plugin
	if err := mgr.Uninstall(context.Background(), "toUninstall"); err != nil {
		t.Fatalf("Manager.Uninstall() err %v, want nil", err)
	}
	// test uninstall non-exist plugin
	expectedErrorMsg := "stat testdata/plugins/non-exist: no such file or directory"
	if err := mgr.Uninstall(context.Background(), "non-exist"); err == nil || err.Error() != expectedErrorMsg {
		t.Fatalf("Manager.Uninstall() err %v, want %s", err, expectedErrorMsg)
	}
}

func metadataJSON(m proto.GetMetadataResponse) []byte {
	d, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return d
}
