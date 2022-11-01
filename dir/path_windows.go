//go:build windows
// +build windows

package dir

import (
	"os"
	"path/filepath"
)

// for unit test
var getenv = os.Getenv

func init() {
	loadWindowsPath()
}

// loadWindowsPath function defines the directory for
// NotationLibexec, NotationConfig
func loadWindowsPath() {
	systemDir := getenv("ProgramData")
	if systemDir == "" {
		// unsupported OS
		panic("environment variable `ProgramData` is not set.")
	}
	SystemConfigDir = filepath.Join(systemDir, notation)

	systemLibexecDir := getenv("ProgramFiles")
	if systemLibexecDir == "" {
		// unsupported OS
		panic("environment variable `ProgramFiles` is not set.")
	}
	systemLibexecDir = filepath.Join(systemLibexecDir, notation)
}
