package dir

func init() {
	loadSystemPath()
}

// loadSystemPath function defines the directory for
// NotationLibexec, NotationConfig
func loadSystemPath() {
	SystemConfigDir = "/Library/Application Support/" + notation
	SystemLibexecDir = "/usr/local/lib/" + notation
}
