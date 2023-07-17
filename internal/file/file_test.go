package file

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/notaryproject/notation-go/dir"
)

func TestLoadNonExistentFile(t *testing.T) {
	dir.UserConfigDir = "testdata/valid"

	var config string
	err := Load("non-existent", &config)
	if err == nil {
		t.Fatalf("load() expected error but not found")
	}
}

func TestLoadSymlink(t *testing.T) {
	root := t.TempDir()
	dir.UserConfigDir = root
	fileName := "symlink"
	os.Symlink("testdata/valid/config.json", filepath.Join(root, fileName))

	expectedError := fmt.Sprintf("\"%s/%s\" is not a regular file (symlinks are not supported)", dir.UserConfigDir, fileName)
	var config string
	err := Load(fileName, &config)
	if err != nil && err.Error() != expectedError {
		t.Fatalf("load() expected error= %s but found= %v", expectedError, err)
	}
}
