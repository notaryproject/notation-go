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

package dir

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestSysFS_SysPath(t *testing.T) {
	wantPath := filepath.FromSlash("/path/notation/config.json")
	fsys := NewSysFS("/path/notation")
	path, err := fsys.SysPath(PathConfigFile)
	if err != nil {
		t.Fatalf("SysPath() failed. err = %v", err)
	}
	if path != wantPath {
		t.Fatalf(`SysPath() failed. got: %q, want: %q`, path, wantPath)
	}
}

func TestOsFs(t *testing.T) {
	wantData := []byte("data")
	fsys := NewSysFS("./testdata")

	// read test file
	path, err := fsys.Open("data.txt")
	if err != nil {
		t.Fatalf("Open() failed. err = %v", err)
	}
	data := make([]byte, 4)
	_, err = path.Read(data)
	if err != nil {
		t.Fatalf("Read() failed. err = %v", err)
	}
	if !bytes.Equal(data, wantData) {
		t.Fatalf("SysFS read failed. got data = %v, want %v", data, wantData)
	}
}

func TestConfigFS(t *testing.T) {
	configFS := ConfigFS()
	path, err := configFS.SysPath(PathConfigFile)
	if err != nil {
		t.Fatalf("SysPath() failed. err = %v", err)
	}
	if path != filepath.Join(UserConfigDir, PathConfigFile) {
		t.Fatalf(`SysPath() failed. got: %q, want: %q`, path, filepath.Join(UserConfigDir, PathConfigFile))
	}
}

func TestPluginFS(t *testing.T) {
	pluginFS := PluginFS()
	path, err := pluginFS.SysPath("plugin")
	if err != nil {
		t.Fatalf("SysPath() failed. err = %v", err)
	}
	if path != filepath.Join(userLibexecDirPath(), PathPlugins, "plugin") {
		t.Fatalf(`SysPath() failed. got: %q, want: %q`, path, filepath.Join(userLibexecDirPath(), PathPlugins, "plugin"))
	}
}

func TestCRLFileCacheFS(t *testing.T) {
	cacheFS := CacheFS()
	path, err := cacheFS.SysPath(PathCRLCache)
	if err != nil {
		t.Fatalf("SysPath() failed. err = %v", err)
	}
	if path != filepath.Join(UserCacheDir, PathCRLCache) {
		t.Fatalf(`SysPath() failed. got: %q, want: %q`, path, UserConfigDir)
	}
}
