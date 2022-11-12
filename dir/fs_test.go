package dir

import (
	"bytes"
	"path/filepath"
	"testing"
)

func Test_sysFS_SysPath(t *testing.T) {
	wantPath := filepath.FromSlash("/path/notation/config.json")
	fsys := NewSysFS("/path/notation")
	path, err := fsys.SysPath(PathConfigFile)
	if err != nil {
		t.Fatalf("SysPath() failed. err = %v", err)
	}
	if path != wantPath {
		t.Fatalf(`SysPath() failed. got: %q, want: %q`, path, wantPath)
	}
}

func Test_OsFs(t *testing.T) {
	wantData := []byte("data")
	fsys := NewSysFS("./testdata")

	// read test file
	path, err := fsys.Open("data.txt")
	if err != nil {
		t.Fatalf("Open() failed. err = %v", err)
	}
	data := make([]byte, 4)
	_, err = path.Read(data)
	if err != nil {
		t.Fatalf("Read() failed. err = %v", err)
	}
	if !bytes.Equal(data, wantData) {
		t.Fatalf("SysFS read failed. got data = %v, want %v", data, wantData)
	}
}
