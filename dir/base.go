package dir

import (
	"os"
	"path/filepath"
	"runtime"
)

const (
	notation = "notation"
)

var (
	// for mocking
	goos          = runtime.GOOS
	userConfigDir = os.UserConfigDir
	userCacheDir  = os.UserCacheDir
	getenv        = os.Getenv

	// systemLibexec directory for binaries not meant to be executed directly
	// by users' shell or scripts
	systemLibexec string
	// systemConfig directory for configurations
	systemConfig string

	// userLibexec is user level libexec directory
	userLibexec string
	// userConfig is user level config directory
	userConfig string
	// userCache for user-specific cache
	userCache string

	// Path is a PathManager pointer
	Path *PathManager
)

func init() {
	loadPath()
}

// loadPath function defines the directory for
// NotationLibexec, NotationConfig, NotationCache
func loadPath() {
	var err error
	// set system config and libexec
	switch goos {
	case "darwin":
		systemConfig = "/Library/Application Support/notation"
		systemLibexec = "/usr/local/lib/notation"
	case "windows":
		systemConfig = getenv("ProgramData")
		if systemConfig == "" {
			// unsupported OS
			panic("environment variable `ProgramData` is not set.")
		}
		systemConfig = filepath.Join(systemConfig, notation)

		systemLibexec = getenv("ProgramFiles")
		if systemLibexec == "" {
			// unsupported OS
			panic("environment variable `ProgramFiles` is not set.")
		}
		systemLibexec = filepath.Join(systemLibexec, notation)

	default:
		systemConfig = "/etc/notation"
		systemLibexec = "/usr/libexec/notation"
	}

	// set user config
	userConfig, err = userConfigDir()
	if err != nil {
		panic(err)
	}
	userConfig = filepath.Join(userConfig, notation)
	// set user libexec
	userLibexec = userConfig
	// set user cache
	userCache, err = userCacheDir()
	if err != nil {
		panic(err)
	}
	userCache = filepath.Join(userCache, notation)

	// set PathManager
	// TODO(JeyJeyGao): The user/system directory priority may change later
	// (https://github.com/notaryproject/notation/issues/203)
	Path = &PathManager{
		ConfigFS: NewUnionDirFS(
			NewRootedFS(userConfig, nil),
			NewRootedFS(systemConfig, nil),
		),
		CacheFS: NewUnionDirFS(
			NewRootedFS(userCache, nil),
		),
		LibexecFS: NewUnionDirFS(
			NewRootedFS(userLibexec, nil),
			NewRootedFS(systemLibexec, nil),
		),
	}
}
