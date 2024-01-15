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
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-plugin-framework-go/plugin"
)

var exampleMetadata = plugin.GetMetadataResponse{
	Name:                      "foo",
	Description:               "friendly",
	Version:                   "1",
	URL:                       "example.com",
	SupportedContractVersions: []string{"1.0"},
	Capabilities:              []plugin.Capability{"cap"}}

func preparePlugin(t *testing.T) string {
	root := t.TempDir()
	src, err := os.Open("./testdata/main.go")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()

	dst, err := os.Create(filepath.Join(root, "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	_, err = io.Copy(dst, src)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(root, "go.mod"), []byte("module main"), 0600)
	if err != nil {
		t.Fatal(err)
	}
	err = os.Mkdir(filepath.Join(root, "foo"), 0700)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "foo", binName("foo"))
	cmd := exec.Command("go", "build", "-o", out)
	cmd.Dir = root
	err = cmd.Run()
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestIntegration(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip()
	}
	root := preparePlugin(t)
	fsys := dir.NewSysFS(root)
	mgr := NewCLIManager(fsys)

	// check list
	plugins, err := mgr.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(plugins) != 1 {
		t.Fatalf("Manager.List() len got %d, want 1", len(plugins))
	}

	// validate and create
	pl, err := mgr.Get(context.Background(), "foo")
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := pl.GetMetadata(context.Background(), &plugin.GetMetadataRequest{})
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(&exampleMetadata, metadata) {
		t.Fatalf("Metadata error. want: %+v, got: %+v", exampleMetadata, metadata)
	}
}
