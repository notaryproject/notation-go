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

//go:build !windows
// +build !windows

package plugin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/notaryproject/notation-go/plugin/proto"
)

func binName(name string) string {
	return proto.Prefix + name
}

// isExecutableFile checks if a file at filePath is user executable
func isExecutableFile(filePath string) (bool, error) {
	fi, err := os.Stat(filePath)
	if err != nil {
		return false, err
	}
	mode := fi.Mode()
	if !mode.IsRegular() {
		return false, ErrNotRegularFile
	}
	return mode.Perm()&0100 != 0, nil
}

// parsePluginName checks if fileName is a valid plugin file name
// and gets plugin name from it based on spec: https://github.com/notaryproject/specifications/blob/main/specs/plugin-extensibility.md#installation
func parsePluginName(fileName string) (string, error) {
	pluginName, found := strings.CutPrefix(fileName, proto.Prefix)
	if !found {
		return "", fmt.Errorf("invalid plugin executable file name. Plugin file name requires format notation-{plugin-name}, but got %s", fileName)
	}
	return pluginName, nil
}

// validatePluginFileExtensionAgainstOS validates if plugin executable file
// name aligns with the runtime OS.
//
// On windows, `.exe` extension is required.
// On other OS, MUST NOT have the `.exe` extension.
func validatePluginFileExtensionAgainstOS(fileName string) error {
	if strings.EqualFold(filepath.Ext(fileName), ".exe") {
		return errors.New("invalid plugin file extension. On OS other than windows, plugin executable file cannot have '.exe' file extension")
	}
	return nil
}
