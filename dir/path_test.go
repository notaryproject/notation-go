package dir

import (
	"testing"
)

func mockGetUserConfig() (string, error) {
	return "/path/", nil
}

func Test_loadPath(t *testing.T) {
	userConfigDir = mockGetUserConfig
	loadUserPath()
	if UserConfigDir != "/path/notation" {
		t.Fatalf(`loadPath() UserConfigDir is incorrect. got: %q, want: "/path/notation"`, UserConfigDir)
	}

	if UserLibexecDir != UserConfigDir {
		t.Fatalf(`loadPath() UserLibexecDir is incorrect. got: %q, want: "/path/notation"`, UserLibexecDir)
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
