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
	"io/fs"
	"os"
	"path/filepath"
)

// SysFS is virtual file system interface that support fs.FS and SysPath method.
type SysFS interface {
	fs.FS

	// SysPath returns the real system path of the given path items in the SysFS.
	SysPath(items ...string) (string, error)
}

type sysFS struct {
	fs.FS
	root string
}

// SysPath returns the real system path of the given name in the SysFS.
func (s sysFS) SysPath(items ...string) (string, error) {
	pathItems := []string{s.root}
	pathItems = append(pathItems, items...)
	return filepath.Join(pathItems...), nil
}

// NewSysFS returns the SysFS for the given root directory.
//
// Support one root directory for rc.1, and may support union directories FS
// after rc.1.
func NewSysFS(root string) SysFS {
	return sysFS{
		FS:   os.DirFS(root),
		root: root}
}

// ConfigFS is the config SysFS
func ConfigFS() SysFS {
	return NewSysFS(userConfigDirPath())
}

// PluginFS is the plugin SysFS
func PluginFS() SysFS {
	return NewSysFS(filepath.Join(userLibexecDirPath(), PathPlugins))
}

// CRLFileCacheFS is the crl file cache SysFS
func CRLFileCacheFS() SysFS {
	return NewSysFS(filepath.Join(userCacheDirPath(), PathCRLFileCache))
}
