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

// package dir implements Notation directory structure.
// [directory spec]: https://github.com/notaryproject/notation/blob/main/specs/directory.md
//
// Example:
//
//   - Read config.json:
//     file, err := dir.ConfigFS().Open(dir.PathConfigFile)
//
//   - Get the path of config.json:
//     path, err := dir.ConfigFS().SysPath(dir.PathConfigFile)
//
//   - Read trustpolicy.json:
//     file, err := dir.ConfigFS().Open(dir.PathTrustPolicy)
//
//   - Get the path of trustpolicy.json:
//     path, err := dir.ConfigFS().SysPath(dir.PathTrustPolicy)
//
//   - Set custom configurations directory:
//     dir.UserConfigDir = '/path/to/configurations/'
//
// Only user level directory is supported for RC.1, and system level directory
// may be added later.
package dir

import (
	"os"
	"path"
	"path/filepath"
)

var (
	UserConfigDir  string // Absolute path of user level {NOTATION_CONFIG}
	UserLibexecDir string // Absolute path of user level {NOTATION_LIBEXEC}
)

const (
	// notation is the directory name for notation configurations.
	notation = "notation"
)

// The relative path to {NOTATION_CONFIG}
const (
	// PathConfigFile is the config.json file relative path.
	PathConfigFile = "config.json"
	// PathSigningKeys is the signingkeys file relative path.
	PathSigningKeys = "signingkeys.json"
	// PathTrustPolicy is the OCI trust policy file relative path.
	// Deprecated
	PathTrustPolicy = PathOCITrustPolicy
	// PathOCITrustPolicy is the OCI trust policy file relative path.
	PathOCITrustPolicy = "trustpolicy.json"
	// PathBlobTrustPolicy is the Blob trust policy file relative path.
	PathBlobTrustPolicy = "trustpolicy.json"
	// PathPlugins is the plugins directory relative path.
	PathPlugins = "plugins"
	// LocalKeysDir is the directory name for local key relative path.
	LocalKeysDir = "localkeys"
	// LocalCertificateExtension defines the extension of the certificate files.
	LocalCertificateExtension = ".crt"
	// LocalKeyExtension defines the extension of the key files.
	LocalKeyExtension = ".key"
	// TrustStoreDir is the directory name of trust store.
	TrustStoreDir = "truststore"
)

var userConfigDir = os.UserConfigDir // for unit test

func init() {
	loadUserPath()
}

// loadUserPath function defines UserConfigDir and UserLibexecDir.
func loadUserPath() {
	// set user config
	userDir, err := userConfigDir()
	if err != nil {
		panic(err)
	}
	UserConfigDir = filepath.Join(userDir, notation)

	// set user libexec
	UserLibexecDir = UserConfigDir
}

// LocalKeyPath returns the local key and local cert relative paths.
func LocalKeyPath(name string) (keyPath, certPath string) {
	basePath := path.Join(LocalKeysDir, name)
	return basePath + LocalKeyExtension, basePath + LocalCertificateExtension
}

// X509TrustStoreDir returns the trust store relative path.
//
// items includes named-store and cert-file names.
// the directory follows the pattern of
// {NOTATION_CONFIG}/truststore/x509/{store-type}/{named-store}/{cert-file}
func X509TrustStoreDir(items ...string) string {
	pathItems := []string{TrustStoreDir, "x509"}
	pathItems = append(pathItems, items...)
	return path.Join(pathItems...)
}
