package dir

import (
	"testing"
)

func Test_sysFS_SysPath(t *testing.T) {
	fsys := NewSysFS("/path/notation")
	path, err := fsys.SysPath(PathConfigFile)
	if err != nil {
		t.Fatalf("SysPath() failed. err = %v", err)
	}
	if path != "/path/notation/config.json" {
		t.Fatalf(`SysPath() failed. got: %q, want: "/path/notation/config.json"`, path)
	}
}
