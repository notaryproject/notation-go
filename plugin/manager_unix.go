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
	"fmt"
	"os"
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
	if !found || pluginName == "" {
		return "", fmt.Errorf("invalid plugin executable file name. Plugin file name requires format notation-{plugin-name}, but got %s", fileName)
	}
	return pluginName, nil
}

// setExecutable sets file to be user executable
func setExecutable(filePath string) error {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return err
	}
	return os.Chmod(filePath, fileInfo.Mode()|os.FileMode(0100))
}
