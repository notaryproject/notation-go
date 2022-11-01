//go:build darwin
// +build darwin

package dir

func init() {
	loadDarwinPath()
}

// loadDarwinPath function defines the directory for
// NotationLibexec, NotationConfig
func loadDarwinPath() {
	SystemConfigDir = "/Library/Application Support/" + notation
	SystemLibexecDir = "/usr/local/lib/" + notation
}
