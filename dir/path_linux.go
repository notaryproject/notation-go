//go:build linux
// +build linux

package dir

func init() {
	loadLinuxPath()
}

// loadLinuxPath function defines the directory for
// NotationLibexec, NotationConfig
func loadLinuxPath() {
	SystemConfigDir = "/etc/" + notation
	SystemLibexecDir = "/usr/libexec/" + notation
}
