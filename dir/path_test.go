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
	"os"
	"path/filepath"
	"testing"
)

func mockGetUserConfig() (string, error) {
	return "/path/", nil
}

func Test_loadPath(t *testing.T) {
	wantDir := filepath.FromSlash("/path/notation")
	userConfigDir = mockGetUserConfig
	loadUserPath()
	if UserConfigDir != wantDir {
		t.Fatalf(`loadPath() UserConfigDir is incorrect. got: %q, want: %q`, UserConfigDir, wantDir)
	}

	if UserLibexecDir != UserConfigDir {
		t.Fatalf(`loadPath() UserLibexecDir is incorrect. got: %q, want: %q`, UserLibexecDir, wantDir)
	}
}

func Test_UserConfigDirPath(t *testing.T) {
	userConfigDir = mockGetUserConfig
	got := UserConfigDirPath()
	if got != "/path/notation" {
		t.Fatalf(`UserConfigDirPath() = %q, want "/path/notation"`, got)
	}
}

func Test_NoHomeVariable(t *testing.T) {
	t.Setenv("HOME", "")
	UserConfigDir = ""
	userConfigDir = os.UserConfigDir
	got := UserConfigDirPath()
	if got != "notation" {
		t.Fatalf(`UserConfigDirPath() = %q, want "notation"`, UserConfigDir)
	}
}

func Test_UserLibexecDirPath(t *testing.T) {
	userConfigDir = mockGetUserConfig
	got := UserLibexecDirPath()
	if got != "/path/notation" {
		t.Fatalf(`UserConfigDirPath() = %q, want "/path/notation"`, got)
	}
}

func TestLocalKeyPath(t *testing.T) {
	userConfigDir = mockGetUserConfig
	loadUserPath()
	gotKeyPath, gotCertPath := LocalKeyPath("web")
	if gotKeyPath != "localkeys/web.key" {
		t.Fatalf(`LocalKeyPath() gotKeyPath = %q, want "localkeys/web.key"`, gotKeyPath)
	}
	if gotCertPath != "localkeys/web.crt" {
		t.Fatalf(`LocalKeyPath() gotCertPath = %q, want "localkeys/web.crt"`, gotCertPath)
	}
}

func TestX509TrustStoreDir(t *testing.T) {
	userConfigDir = mockGetUserConfig
	loadUserPath()
	if got := X509TrustStoreDir("ca", "web"); got != "truststore/x509/ca/web" {
		t.Fatalf(`X509TrustStoreDir() = %q, want "truststore/x509/ca/web"`, got)
	}
}
