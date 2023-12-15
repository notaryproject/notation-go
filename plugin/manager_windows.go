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
	"os"
	"path/filepath"
	"strings"

	"github.com/notaryproject/notation-go/plugin/proto"
)

func binName(name string) string {
	return proto.Prefix + name + ".exe"
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
