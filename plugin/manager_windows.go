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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/notaryproject/notation-go/internal/file"
	"github.com/notaryproject/notation-plugin-framework-go/plugin"
)

func binName(name string) string {
	return plugin.BinaryPrefix + name + ".exe"
}

// isExecutableFile checks if a file at filePath is executable
func isExecutableFile(filePath string) (bool, error) {
	fi, err := os.Stat(filePath)
	if err != nil {
		return false, err
	}
	if !fi.Mode().IsRegular() {
		return false, ErrNotRegularFile
	}
	return strings.EqualFold(filepath.Ext(filepath.Base(filePath)), ".exe"), nil
}

// parsePluginName checks if fileName is a valid plugin file name
// and gets plugin name from it based on spec: https://github.com/notaryproject/specifications/blob/main/specs/plugin-extensibility.md#installation
func parsePluginName(fileName string) (string, error) {
	if !strings.EqualFold(filepath.Ext(fileName), ".exe") {
		return "", fmt.Errorf("invalid plugin executable file name. Plugin file name requires format notation-{plugin-name}.exe, but got %s", fileName)
	}
	fname := file.TrimFileExtension(fileName)
	pluginName, found := strings.CutPrefix(fname, plugin.BinaryPrefix)
	if !found || pluginName == "" {
		return "", fmt.Errorf("invalid plugin executable file name. Plugin file name requires format notation-{plugin-name}.exe, but got %s", fileName)
	}
	return pluginName, nil
}

// setExecutable returns error on Windows. User needs to install the correct
// plugin file.
func setExecutable(filePath string) error {
	return fmt.Errorf(`plugin executable file must have file extension ".exe", but got %q`, filepath.Base(filePath))
}
