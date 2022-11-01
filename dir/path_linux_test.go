//go:build linux
// +build linux

package dir

import "testing"

func Test_loadLinuxPath(t *testing.T) {
	loadLinuxPath()
	if SystemConfigDir != "/etc/notation" {
		t.Fatalf(`SystemConfigDir for Linux is incorrect. got: %q, want: "/etc/notation"`, SystemConfigDir)
	}

	if SystemLibexecDir != "/usr/libexec/notation" {
		t.Fatalf(`SystemLibexecDir for Linux is incorrect. got: %q, want: "/usr/libexec/notation"`, SystemLibexecDir)
	}
}
