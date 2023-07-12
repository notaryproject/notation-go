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

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/notaryproject/notation-go/dir"
)

func TestLoadNonExistentFile(t *testing.T) {
	dir.UserConfigDir = "testdata/valid"

	var config string
	err := load("non-existent", &config)
	if err == nil {
		t.Fatalf("load() expected error but not found")
	}
}

func TestLoadSymlink(t *testing.T) {
	root := t.TempDir()
	dir.UserConfigDir = root
	fileName := "symlink"
	os.Symlink("testdata/valid/config.json", filepath.Join(root, fileName))

	expectedError := fmt.Sprintf("\"%s/%s\" is not a regular file (symlinks are not supported)", dir.UserConfigDir, fileName)
	var config string
	err := load(fileName, &config)
	if err != nil && err.Error() != expectedError {
		t.Fatalf("load() expected error= %s but found= %v", expectedError, err)
	}
}
