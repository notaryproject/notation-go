package dir

import "testing"

func Test_loadDarwinPath(t *testing.T) {
	loadSystemPath()
	if SystemConfigDir != "/Library/Application Support/notation" {
		t.Fatalf(`SystemConfigDir for Darwin is incorrect. got: %q, want: "/Library/Application Support/notation"`, SystemConfigDir)
	}

	if SystemLibexecDir != "/usr/local/lib/notation" {
		t.Fatalf(`SystemLibexecDir for Darwin is incorrect. got: %q, want: "/usr/local/lib/notation"`, SystemLibexecDir)
	}
}
