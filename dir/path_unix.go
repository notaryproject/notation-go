package dir

func init() {
	loadSystemPath()
}

// loadSystemPath function defines the directory for
// NotationLibexec, NotationConfig
func loadSystemPath() {
	SystemConfigDir = "/etc/" + notation
	SystemLibexecDir = "/usr/libexec/" + notation
}
