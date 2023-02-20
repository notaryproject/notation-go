package dir

import (
	"os"
	"path/filepath"
	"testing"
)

func mockGetUserConfig() (string, error) {
	return "/path/", nil
}

func Test_loadPath_Default(t *testing.T) {
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

func Test_loadPath_With_Env(t *testing.T) {
	wantConfigDir := filepath.FromSlash("/my_notation/config")
	wantLibexecDir := filepath.FromSlash("/my_notation/libexec")
	userConfigDir = mockGetUserConfig
	os.Setenv("NOTATION_CONFIG", wantConfigDir)
	os.Setenv("NOTATION_LIBEXEC", wantLibexecDir)
	loadUserPath()
	if UserConfigDir != wantConfigDir {
		t.Fatalf(`loadPath() UserConfigDir is incorrect. got: %q, want: %q`, UserConfigDir, wantConfigDir)
	}

	if UserLibexecDir != wantLibexecDir {
		t.Fatalf(`loadPath() UserLibexecDir is incorrect. got: %q, want: %q`, UserLibexecDir, wantLibexecDir)
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
