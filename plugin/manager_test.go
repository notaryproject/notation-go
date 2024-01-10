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
	"path/filepath"
	"reflect"
	"runtime"
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

type testInstallCommander struct {
	existedPluginFilePath string
	existedPluginStdout   []byte
	existedPluginStderr   []byte
	existedPluginErr      error
	newPluginFilePath     string
	newPluginStdout       []byte
	newPluginStderr       []byte
	newPluginErr          error
	err                   error
}

func (t testInstallCommander) Output(ctx context.Context, path string, command proto.Command, req []byte) ([]byte, []byte, error) {
	if path == t.existedPluginFilePath {
		return t.existedPluginStdout, t.existedPluginStderr, t.existedPluginErr
	}
	if path == t.newPluginFilePath {
		return t.newPluginStdout, t.newPluginStderr, t.newPluginErr
	}
	return nil, nil, t.err
}

var validMetadata = proto.GetMetadataResponse{
	Name: "foo", Description: "friendly", Version: "1.0.0", URL: "example.com",
	SupportedContractVersions: []string{"1.0"}, Capabilities: []proto.Capability{proto.CapabilitySignatureGenerator},
}

var validMetadataHigherVersion = proto.GetMetadataResponse{
	Name: "foo", Description: "friendly", Version: "1.1.0", URL: "example.com",
	SupportedContractVersions: []string{"1.0"}, Capabilities: []proto.Capability{proto.CapabilitySignatureGenerator},
}

var validMetadataLowerVersion = proto.GetMetadataResponse{
	Name: "foo", Description: "friendly", Version: "0.1.0", URL: "example.com",
	SupportedContractVersions: []string{"1.0"}, Capabilities: []proto.Capability{proto.CapabilitySignatureGenerator},
}

var validMetadataBar = proto.GetMetadataResponse{
	Name: "bar", Description: "friendly", Version: "1.0.0", URL: "example.com",
	SupportedContractVersions: []string{"1.0"}, Capabilities: []proto.Capability{proto.CapabilitySignatureGenerator},
}

var validMetadataBarExample = proto.GetMetadataResponse{
	Name: "bar.example.plugin", Description: "friendly", Version: "1.0.0", URL: "example.com",
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
	if runtime.GOOS == "windows" {
		t.Skip("skipping test on Windows")
	}
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

func TestManager_Install(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping test on Windows")
	}
	existedPluginFilePath := "testdata/plugins/foo/notation-foo"
	newPluginFilePath := "testdata/foo/notation-foo"
	newPluginDir := filepath.Dir(newPluginFilePath)
	if err := os.MkdirAll(newPluginDir, 0777); err != nil {
		t.Fatalf("failed to create %s: %v", newPluginDir, err)
	}
	defer os.RemoveAll(newPluginDir)
	if err := createFileAndChmod(newPluginFilePath, 0700); err != nil {
		t.Fatal(err)
	}
	mgr := NewCLIManager(mockfs.NewSysFSWithRootMock(fstest.MapFS{}, "testdata/plugins"))

	t.Run("success install with higher version", func(t *testing.T) {
		executor = testInstallCommander{
			existedPluginFilePath: existedPluginFilePath,
			newPluginFilePath:     newPluginFilePath,
			existedPluginStdout:   metadataJSON(validMetadata),
			newPluginStdout:       metadataJSON(validMetadataHigherVersion),
		}
		installOpts := CLIInstallOptions{
			PluginPath: newPluginFilePath,
		}
		existingPluginMetadata, newPluginMetadata, err := mgr.Install(context.Background(), installOpts)
		if err != nil {
			t.Fatalf("expecting error to be nil, but got %v", err)
		}
		if existingPluginMetadata.Version != validMetadata.Version {
			t.Fatalf("existing plugin version mismatch, existing plugin version: %s, but got: %s", validMetadata.Version, existingPluginMetadata.Version)
		}
		if newPluginMetadata.Version != validMetadataHigherVersion.Version {
			t.Fatalf("new plugin version mismatch, new plugin version: %s, but got: %s", validMetadataHigherVersion.Version, newPluginMetadata.Version)
		}
	})

	t.Run("success install with lower version and overwrite", func(t *testing.T) {
		executor = testInstallCommander{
			existedPluginFilePath: existedPluginFilePath,
			newPluginFilePath:     newPluginFilePath,
			existedPluginStdout:   metadataJSON(validMetadata),
			newPluginStdout:       metadataJSON(validMetadataLowerVersion),
		}
		installOpts := CLIInstallOptions{
			PluginPath: newPluginFilePath,
			Overwrite:  true,
		}
		if _, _, err := mgr.Install(context.Background(), installOpts); err != nil {
			t.Fatalf("expecting error to be nil, but got %v", err)
		}
	})

	t.Run("success install without existing plugin", func(t *testing.T) {
		newPluginFilePath := "testdata/bar/notation-bar"
		newPluginDir := filepath.Dir(newPluginFilePath)
		if err := os.MkdirAll(newPluginDir, 0777); err != nil {
			t.Fatalf("failed to create %s: %v", newPluginDir, err)
		}
		defer os.RemoveAll(newPluginDir)
		if err := createFileAndChmod(newPluginFilePath, 0700); err != nil {
			t.Fatal(err)
		}
		executor = testInstallCommander{
			newPluginFilePath: newPluginFilePath,
			newPluginStdout:   metadataJSON(validMetadataBar),
		}
		defer mgr.Uninstall(context.Background(), "bar")
		installOpts := CLIInstallOptions{
			PluginPath: newPluginFilePath,
		}
		existingPluginMetadata, newPluginMetadata, err := mgr.Install(context.Background(), installOpts)
		if err != nil {
			t.Fatalf("expecting error to be nil, but got %v", err)
		}
		if existingPluginMetadata != nil {
			t.Fatalf("expecting existingPluginMetadata to be nil, but got %v", existingPluginMetadata)
		}
		if newPluginMetadata.Version != validMetadataBar.Version {
			t.Fatalf("new plugin version mismatch, new plugin version: %s, but got: %s", validMetadataBar.Version, newPluginMetadata.Version)
		}
	})

	t.Run("success install with file extension", func(t *testing.T) {
		newPluginFilePath := "testdata/bar/notation-bar.example.plugin"
		newPluginDir := filepath.Dir(newPluginFilePath)
		if err := os.MkdirAll(newPluginDir, 0777); err != nil {
			t.Fatalf("failed to create %s: %v", newPluginDir, err)
		}
		defer os.RemoveAll(newPluginDir)
		if err := createFileAndChmod(newPluginFilePath, 0700); err != nil {
			t.Fatal(err)
		}
		executor = testInstallCommander{
			newPluginFilePath: newPluginFilePath,
			newPluginStdout:   metadataJSON(validMetadataBarExample),
		}
		defer mgr.Uninstall(context.Background(), "bar.example.plugin")
		installOpts := CLIInstallOptions{
			PluginPath: newPluginFilePath,
		}
		existingPluginMetadata, newPluginMetadata, err := mgr.Install(context.Background(), installOpts)
		if err != nil {
			t.Fatalf("expecting error to be nil, but got %v", err)
		}
		if existingPluginMetadata != nil {
			t.Fatalf("expecting existingPluginMetadata to be nil, but got %v", existingPluginMetadata)
		}
		if newPluginMetadata.Version != validMetadataBar.Version {
			t.Fatalf("new plugin version mismatch, new plugin version: %s, but got: %s", validMetadataBar.Version, newPluginMetadata.Version)
		}
	})

	t.Run("fail to install due to equal version", func(t *testing.T) {
		executor = testInstallCommander{
			existedPluginFilePath: existedPluginFilePath,
			newPluginFilePath:     newPluginFilePath,
			existedPluginStdout:   metadataJSON(validMetadata),
			newPluginStdout:       metadataJSON(validMetadata),
		}
		installOpts := CLIInstallOptions{
			PluginPath: newPluginFilePath,
		}
		expectedErrorMsg := "plugin foo with version 1.0.0 already exists"
		_, _, err := mgr.Install(context.Background(), installOpts)
		if err == nil || err.Error() != expectedErrorMsg {
			t.Fatalf("expecting error %s, but got %v", expectedErrorMsg, err)
		}
	})

	t.Run("fail to install due to lower version", func(t *testing.T) {
		executor = testInstallCommander{
			existedPluginFilePath: existedPluginFilePath,
			newPluginFilePath:     newPluginFilePath,
			existedPluginStdout:   metadataJSON(validMetadata),
			newPluginStdout:       metadataJSON(validMetadataLowerVersion),
		}
		installOpts := CLIInstallOptions{
			PluginPath: newPluginFilePath,
		}
		expectedErrorMsg := "failed to install plugin foo. The installing plugin version 0.1.0 is lower than the existing plugin version 1.0.0"
		_, _, err := mgr.Install(context.Background(), installOpts)
		if err == nil || err.Error() != expectedErrorMsg {
			t.Fatalf("expecting error %s, but got %v", expectedErrorMsg, err)
		}
	})

	t.Run("fail to install due to wrong plugin executable file name format", func(t *testing.T) {
		newPluginFilePath := "testdata/bar/bar"
		newPluginDir := filepath.Dir(newPluginFilePath)
		if err := os.MkdirAll(newPluginDir, 0777); err != nil {
			t.Fatalf("failed to create %s: %v", newPluginDir, err)
		}
		defer os.RemoveAll(newPluginDir)
		if err := createFileAndChmod(newPluginFilePath, 0700); err != nil {
			t.Fatal(err)
		}
		executor = testInstallCommander{
			newPluginFilePath: newPluginFilePath,
			newPluginStdout:   metadataJSON(validMetadataBar),
		}
		installOpts := CLIInstallOptions{
			PluginPath: newPluginFilePath,
		}
		expectedErrorMsg := "failed to read plugin name from input file: invalid plugin executable file name. Plugin file name requires format notation-{plugin-name}, but got bar"
		_, _, err := mgr.Install(context.Background(), installOpts)
		if err == nil || err.Error() != expectedErrorMsg {
			t.Fatalf("expecting error %s, but got %v", expectedErrorMsg, err)
		}
	})

	t.Run("fail to install due to plugin executable file name missing plugin name", func(t *testing.T) {
		newPluginFilePath := "testdata/bar/notation-"
		newPluginDir := filepath.Dir(newPluginFilePath)
		if err := os.MkdirAll(newPluginDir, 0777); err != nil {
			t.Fatalf("failed to create %s: %v", newPluginDir, err)
		}
		defer os.RemoveAll(newPluginDir)
		if err := createFileAndChmod(newPluginFilePath, 0700); err != nil {
			t.Fatal(err)
		}
		executor = testInstallCommander{
			newPluginFilePath: newPluginFilePath,
			newPluginStdout:   metadataJSON(validMetadataBar),
		}
		installOpts := CLIInstallOptions{
			PluginPath: newPluginFilePath,
		}
		expectedErrorMsg := "failed to read plugin name from input file: invalid plugin executable file name. Plugin file name requires format notation-{plugin-name}, but got notation-"
		_, _, err := mgr.Install(context.Background(), installOpts)
		if err == nil || err.Error() != expectedErrorMsg {
			t.Fatalf("expecting error %s, but got %v", expectedErrorMsg, err)
		}
	})

	t.Run("fail to install due to wrong plugin file permission", func(t *testing.T) {
		newPluginFilePath := "testdata/bar/notation-bar"
		newPluginDir := filepath.Dir(newPluginFilePath)
		if err := os.MkdirAll(newPluginDir, 0777); err != nil {
			t.Fatalf("failed to create %s: %v", newPluginDir, err)
		}
		defer os.RemoveAll(newPluginDir)
		if err := createFileAndChmod(newPluginFilePath, 0600); err != nil {
			t.Fatal(err)
		}
		executor = testInstallCommander{
			newPluginFilePath: newPluginFilePath,
			newPluginStdout:   metadataJSON(validMetadataBar),
		}
		installOpts := CLIInstallOptions{
			PluginPath: newPluginFilePath,
		}
		expectedErrorMsg := "input file is not executable"
		_, _, err := mgr.Install(context.Background(), installOpts)
		if err == nil || err.Error() != expectedErrorMsg {
			t.Fatalf("expecting error %s, but got %v", expectedErrorMsg, err)
		}
	})

	t.Run("fail to install due to new plugin executable file does not exist", func(t *testing.T) {
		newPluginFilePath := "testdata/bar/notation-bar"
		executor = testInstallCommander{
			newPluginFilePath: newPluginFilePath,
			newPluginStdout:   metadataJSON(validMetadataBar),
		}
		installOpts := CLIInstallOptions{
			PluginPath: newPluginFilePath,
		}
		expectedErrorMsg := "failed to read plugin from input directory: stat testdata/bar/notation-bar: no such file or directory"
		_, _, err := mgr.Install(context.Background(), installOpts)
		if err == nil || err.Error() != expectedErrorMsg {
			t.Fatalf("expecting error %s, but got %v", expectedErrorMsg, err)
		}
	})

	t.Run("fail to install due to invalid new plugin metadata", func(t *testing.T) {
		newPluginFilePath := "testdata/bar/notation-bar"
		newPluginDir := filepath.Dir(newPluginFilePath)
		if err := os.MkdirAll(newPluginDir, 0777); err != nil {
			t.Fatalf("failed to create %s: %v", newPluginDir, err)
		}
		defer os.RemoveAll(newPluginDir)
		if err := createFileAndChmod(newPluginFilePath, 0700); err != nil {
			t.Fatal(err)
		}
		executor = testInstallCommander{
			newPluginFilePath: newPluginFilePath,
			newPluginStdout:   metadataJSON(invalidMetadataName),
		}
		installOpts := CLIInstallOptions{
			PluginPath: newPluginFilePath,
		}
		expectedErrorMsg := "failed to get metadata of new plugin: executable name must be \"notation-foobar\" instead of \"notation-bar\""
		_, _, err := mgr.Install(context.Background(), installOpts)
		if err == nil || err.Error() != expectedErrorMsg {
			t.Fatalf("expecting error %s, but got %v", expectedErrorMsg, err)
		}
	})

	t.Run("fail to install due to invalid existing plugin metadata", func(t *testing.T) {
		executor = testInstallCommander{
			existedPluginFilePath: existedPluginFilePath,
			newPluginFilePath:     newPluginFilePath,
			existedPluginStdout:   metadataJSON(validMetadataBar),
			newPluginStdout:       metadataJSON(validMetadata),
		}
		installOpts := CLIInstallOptions{
			PluginPath: newPluginFilePath,
		}
		expectedErrorMsg := "failed to get metadata of existing plugin: executable name must be \"notation-bar\" instead of \"notation-foo\""
		_, _, err := mgr.Install(context.Background(), installOpts)
		if err == nil || err.Error() != expectedErrorMsg {
			t.Fatalf("expecting error %s, but got %v", expectedErrorMsg, err)
		}
	})

	t.Run("success to install with overwrite and invalid existing plugin metadata", func(t *testing.T) {
		executor = testInstallCommander{
			existedPluginFilePath: existedPluginFilePath,
			newPluginFilePath:     newPluginFilePath,
			existedPluginStdout:   metadataJSON(validMetadataBar),
			newPluginStdout:       metadataJSON(validMetadata),
		}
		installOpts := CLIInstallOptions{
			PluginPath: newPluginFilePath,
			Overwrite:  true,
		}
		_, _, err := mgr.Install(context.Background(), installOpts)
		if err != nil {
			t.Fatalf("expecting error to be nil, but got %v", err)
		}
	})

	t.Run("success to install from plugin dir", func(t *testing.T) {
		existedPluginFilePath := "testdata/plugins/foo/notation-foo"
		newPluginFilePath := "testdata/foo/notation-foo"
		newPluginLibPath := "testdata/foo/notation-libfoo"
		newPluginDir := filepath.Dir(newPluginFilePath)
		if err := os.MkdirAll(newPluginDir, 0777); err != nil {
			t.Fatalf("failed to create %s: %v", newPluginDir, err)
		}
		defer os.RemoveAll(newPluginDir)
		if err := createFileAndChmod(newPluginFilePath, 0700); err != nil {
			t.Fatal(err)
		}
		if err := createFileAndChmod(newPluginLibPath, 0600); err != nil {
			t.Fatal(err)
		}
		executor = testInstallCommander{
			existedPluginFilePath: existedPluginFilePath,
			newPluginFilePath:     newPluginFilePath,
			existedPluginStdout:   metadataJSON(validMetadata),
			newPluginStdout:       metadataJSON(validMetadataHigherVersion),
		}
		installOpts := CLIInstallOptions{
			PluginPath: newPluginDir,
		}
		existingPluginMetadata, newPluginMetadata, err := mgr.Install(context.Background(), installOpts)
		if err != nil {
			t.Fatalf("expecting nil error, but got %v", err)
		}
		if existingPluginMetadata.Version != "1.0.0" {
			t.Fatalf("expecting existing plugin metadata to be 1.0.0, but got %s", existingPluginMetadata.Version)
		}
		if newPluginMetadata.Version != "1.1.0" {
			t.Fatalf("expecting new plugin metadata to be 1.1.0, but got %s", newPluginMetadata.Version)
		}
	})

	t.Run("success to install from plugin dir with no executable file and one valid candidate file", func(t *testing.T) {
		existedPluginFilePath := "testdata/plugins/foo/notation-foo"
		newPluginFilePath := "testdata/foo/notation-foo"
		newPluginLibPath := "testdata/foo/libfoo"
		newPluginDir := filepath.Dir(newPluginFilePath)
		if err := os.MkdirAll(newPluginDir, 0777); err != nil {
			t.Fatalf("failed to create %s: %v", newPluginDir, err)
		}
		defer os.RemoveAll(newPluginDir)
		if err := createFileAndChmod(newPluginFilePath, 0600); err != nil {
			t.Fatal(err)
		}
		if err := createFileAndChmod(newPluginLibPath, 0600); err != nil {
			t.Fatal(err)
		}
		executor = testInstallCommander{
			existedPluginFilePath: existedPluginFilePath,
			newPluginFilePath:     newPluginFilePath,
			existedPluginStdout:   metadataJSON(validMetadata),
			newPluginStdout:       metadataJSON(validMetadataHigherVersion),
		}
		installOpts := CLIInstallOptions{
			PluginPath: newPluginDir,
		}
		existingPluginMetadata, newPluginMetadata, err := mgr.Install(context.Background(), installOpts)
		if err != nil {
			t.Fatalf("expecting nil error, but got %v", err)
		}
		if existingPluginMetadata.Version != "1.0.0" {
			t.Fatalf("expecting existing plugin metadata to be 1.0.0, but got %s", existingPluginMetadata.Version)
		}
		if newPluginMetadata.Version != "1.1.0" {
			t.Fatalf("expecting new plugin metadata to be 1.1.0, but got %s", newPluginMetadata.Version)
		}
	})

	t.Run("fail to install from plugin dir due to more than one candidate plugin executable files", func(t *testing.T) {
		existedPluginFilePath := "testdata/plugins/foo/notation-foo"
		newPluginFilePath := "testdata/foo/notation-foo1"
		newPluginFilePath2 := "testdata/foo/notation-foo2"
		newPluginDir := filepath.Dir(newPluginFilePath)
		if err := os.MkdirAll(newPluginDir, 0777); err != nil {
			t.Fatalf("failed to create %s: %v", newPluginDir, err)
		}
		defer os.RemoveAll(newPluginDir)
		if err := createFileAndChmod(newPluginFilePath, 0600); err != nil {
			t.Fatal(err)
		}
		if err := createFileAndChmod(newPluginFilePath2, 0600); err != nil {
			t.Fatal(err)
		}
		executor = testInstallCommander{
			existedPluginFilePath: existedPluginFilePath,
			newPluginFilePath:     newPluginFilePath,
			existedPluginStdout:   metadataJSON(validMetadata),
			newPluginStdout:       metadataJSON(validMetadataHigherVersion),
		}
		installOpts := CLIInstallOptions{
			PluginPath: newPluginDir,
		}
		expectedErrorMsg := "failed to read plugin from input directory: no plugin executable file was found"
		_, _, err := mgr.Install(context.Background(), installOpts)
		if err == nil || err.Error() != expectedErrorMsg {
			t.Fatalf("expecting error %s, but got %v", expectedErrorMsg, err)
		}
	})

	t.Run("fail to install from plugin dir due to more than one plugin executable files", func(t *testing.T) {
		existedPluginFilePath := "testdata/plugins/foo/notation-foo"
		newPluginFilePath := "testdata/foo/notation-foo1"
		newPluginFilePath2 := "testdata/foo/notation-foo2"
		newPluginDir := filepath.Dir(newPluginFilePath)
		if err := os.MkdirAll(newPluginDir, 0777); err != nil {
			t.Fatalf("failed to create %s: %v", newPluginDir, err)
		}
		defer os.RemoveAll(newPluginDir)
		if err := createFileAndChmod(newPluginFilePath, 0700); err != nil {
			t.Fatal(err)
		}
		if err := createFileAndChmod(newPluginFilePath2, 0700); err != nil {
			t.Fatal(err)
		}
		executor = testInstallCommander{
			existedPluginFilePath: existedPluginFilePath,
			newPluginFilePath:     newPluginFilePath,
			existedPluginStdout:   metadataJSON(validMetadata),
			newPluginStdout:       metadataJSON(validMetadataHigherVersion),
		}
		installOpts := CLIInstallOptions{
			PluginPath: newPluginDir,
		}
		expectedErrorMsg := "failed to read plugin from input directory: found more than one plugin executable files"
		_, _, err := mgr.Install(context.Background(), installOpts)
		if err == nil || err.Error() != expectedErrorMsg {
			t.Fatalf("expecting error %s, but got %v", expectedErrorMsg, err)
		}
	})
}

func TestManager_Uninstall(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping test on Windows")
	}
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

func TestParsePluginName(t *testing.T) {
	pluginName, err := parsePluginName("notation-my-plugin")
	if err != nil {
		t.Fatalf("expected nil err, but got %v", err)
	}
	if pluginName != "my-plugin" {
		t.Fatalf("expected plugin name my-plugin, but got %s", pluginName)
	}

	if runtime.GOOS == "windows" {
		pluginName, err = parsePluginName("notation-my-plugin.exe")
		if err != nil {
			t.Fatalf("expected nil err, but got %v", err)
		}
		if pluginName != "my-plugin" {
			t.Fatalf("expected plugin name my-plugin, but got %s", pluginName)
		}

		pluginName, err = parsePluginName("notation-com.plugin")
		if err != nil {
			t.Fatalf("expected nil err, but got %v", err)
		}
		if pluginName != "com.plugin" {
			t.Fatalf("expected plugin name com.plugin, but got %s", pluginName)
		}

		expectedErrorMsg := "invalid plugin executable file name. Plugin file name requires format notation-{plugin-name}.exe, but got my-plugin.exe"
		_, err = parsePluginName("my-plugin.exe")
		if err == nil || err.Error() != expectedErrorMsg {
			t.Fatalf("expected %s, but got %v", expectedErrorMsg, err)
		}

		expectedErrorMsg = "invalid plugin executable file name. Plugin file name requires format notation-{plugin-name}.exe, but got notation-.exe"
		_, err = parsePluginName("notation-.exe")
		if err == nil || err.Error() != expectedErrorMsg {
			t.Fatalf("expected %s, but got %v", expectedErrorMsg, err)
		}

		expectedErrorMsg = "invalid plugin executable file name. Plugin file name requires format notation-{plugin-name}.exe, but got my-plugin"
		_, err = parsePluginName("my-plugin")
		if err == nil || err.Error() != expectedErrorMsg {
			t.Fatalf("expected %s, but got %v", expectedErrorMsg, err)
		}
	} else {
		pluginName, err = parsePluginName("notation-com.example.plugin")
		if err != nil {
			t.Fatalf("expected nil err, but got %v", err)
		}
		if pluginName != "com.example.plugin" {
			t.Fatalf("expected plugin name com.example.plugin, but got %s", pluginName)
		}

		expectedErrorMsg := "invalid plugin executable file name. Plugin file name requires format notation-{plugin-name}, but got myPlugin"
		_, err = parsePluginName("myPlugin")
		if err == nil || err.Error() != expectedErrorMsg {
			t.Fatalf("expected %s, but got %v", expectedErrorMsg, err)
		}

		expectedErrorMsg = "invalid plugin executable file name. Plugin file name requires format notation-{plugin-name}, but got my-plugin"
		_, err = parsePluginName("my-plugin")
		if err == nil || err.Error() != expectedErrorMsg {
			t.Fatalf("expected %s, but got %v", expectedErrorMsg, err)
		}

		expectedErrorMsg = "invalid plugin executable file name. Plugin file name requires format notation-{plugin-name}, but got notation-"
		_, err = parsePluginName("notation-")
		if err == nil || err.Error() != expectedErrorMsg {
			t.Fatalf("expected %s, but got %v", expectedErrorMsg, err)
		}
	}
}

func metadataJSON(m proto.GetMetadataResponse) []byte {
	d, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return d
}

func createFileAndChmod(path string, mode fs.FileMode) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	return f.Close()
}
