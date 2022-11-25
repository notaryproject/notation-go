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
	"github.com/notaryproject/notation-go/plugin/proto"
)

var exampleMetadata = proto.GetMetadataResponse{
	Name:                      "foo",
	Description:               "friendly",
	Version:                   "1",
	URL:                       "example.com",
	SupportedContractVersions: []string{"1.0"},
	Capabilities:              []proto.Capability{"cap"}}

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
	plugin, err := mgr.Get(context.Background(), "foo")
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := plugin.GetMetadata(context.Background(), &proto.GetMetadataRequest{})
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(&exampleMetadata, metadata) {
		t.Fatalf("Metadata error. want: %+v, got: %+v", exampleMetadata, metadata)
	}
}
