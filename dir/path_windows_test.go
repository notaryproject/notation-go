package dir

import "testing"

func mockGetenv(name string) string {
	return "/path/"
}

func Test_loadWindowsPath(t *testing.T) {
	getenv = mockGetenv
	loadSystemPath()
	if SystemConfigDir != "/path/notation" {
		t.Fatalf(`SystemConfigDir for Windows is incorrect. got: %q, want: "/path/notation"`, SystemConfigDir)
	}

	if SystemLibexecDir != "/path/notation" {
		t.Fatalf(`SystemLibexecDir for Windows is incorrect. got: %q, want: "/path/notation"`, SystemLibexecDir)
	}
}
