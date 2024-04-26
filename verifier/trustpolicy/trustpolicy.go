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

// Package trustpolicy provides functionalities for trust policy document
// and trust policy statements.
package trustpolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/internal/trustpolicy"
)

// LoadTrustPolicyDocument loads a trust policy document, which supports all
// versions of trust policy
func LoadTrustPolicyDocument() (*trustpolicy.Document, error) {
	jsonFile, err := openTrustPlicy()
	if err != nil {
		return nil, err
	}
	defer jsonFile.Close()

	// get version
	base := &struct {
		Version string `json:"version"`
	}{}
	err = json.NewDecoder(jsonFile).Decode(base)
	if err != nil {
		return nil, fmt.Errorf("malformed trust policy. To create a trust policy, see: %s", trustPolicyLink)
	}

	// parse trust policy based on version
	switch base.Version {
	case "1.0":
		policyDocument := &Document{}
		err = json.NewDecoder(jsonFile).Decode(policyDocument)
		if err != nil {
			return nil, fmt.Errorf("malformed trust policy. To create a trust policy, see: %s", trustPolicyLink)
		}
		return policyDocument.ToTrustPolicyDocument()
	default:
		return nil, fmt.Errorf("unsupported trust policy version %q", base.Version)
	}
}

func openTrustPlicy() (*os.File, error) {
	path, err := dir.ConfigFS().SysPath(dir.PathTrustPolicy)
	if err != nil {
		return nil, err
	}

	// throw error if path is a directory or a symlink or does not exist.
	fileInfo, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("trust policy is not present. To create a trust policy, see: %s", trustPolicyLink)
		}
		return nil, err
	}

	mode := fileInfo.Mode()
	if mode.IsDir() || mode&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("trust policy is not a regular file (symlinks are not supported). To create a trust policy, see: %s", trustPolicyLink)
	}

	jsonFile, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, fmt.Errorf("unable to read trust policy due to file permissions, please verify the permissions of %s", filepath.Join(dir.UserConfigDir, dir.PathTrustPolicy))
		}
		return nil, err
	}
	return jsonFile, nil
}
