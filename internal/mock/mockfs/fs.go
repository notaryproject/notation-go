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

package mockfs

import (
	"io/fs"
	"path/filepath"

	"github.com/notaryproject/notation-go/dir"
)

type sysFSMock struct {
	fs.FS
	root string
}

// SysPath returns the system path of the FS.
func (s sysFSMock) SysPath(items ...string) (string, error) {
	pathItems := []string{s.root}
	pathItems = append(pathItems, items...)
	return filepath.Join(pathItems...), nil
}

// NewSysFSMock returns a SysFS mock of the given FS.
func NewSysFSMock(fsys fs.FS) dir.SysFS {
	return sysFSMock{
		FS:   fsys,
		root: ""}
}

// NewSysFSWithRootMock returns a SysFS mock of the given fs and
// a root directory
func NewSysFSWithRootMock(fsys fs.FS, root string) dir.SysFS {
	return sysFSMock{
		FS:   fsys,
		root: root}
}
