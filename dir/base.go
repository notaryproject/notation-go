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

	// SystemLibexec directory for binaries not meant to be executed directly
	// by users' shell or scripts
	SystemLibexec string
	// SystemConfig directory for configurations
	SystemConfig string

	// UserLibexec is user level libexec directory
	UserLibexec string
	// UserConfig is user level config directory
	UserConfig string
	// UserCache for user-specific cache
	UserCache string

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
		SystemConfig = "/Library/Application Support/notation"
		SystemLibexec = "/usr/local/lib/notation"
	case "windows":
		SystemConfig = getenv("ProgramData")
		if SystemConfig == "" {
			// unsupported OS
			panic("environment variable `ProgramData` is not set.")
		}
		SystemConfig = filepath.Join(SystemConfig, notation)

		SystemLibexec = getenv("ProgramFiles")
		if SystemLibexec == "" {
			// unsupported OS
			panic("environment variable `ProgramFiles` is not set.")
		}
		SystemLibexec = filepath.Join(SystemLibexec, notation)

	default:
		SystemConfig = "/etc/notation"
		SystemLibexec = "/usr/libexec/notation"
	}

	// set user config
	UserConfig, err = userConfigDir()
	if err != nil {
		panic(err)
	}
	UserConfig = filepath.Join(UserConfig, notation)
	// set user libexec
	UserLibexec = UserConfig
	// set user cache
	UserCache, err = userCacheDir()
	if err != nil {
		panic(err)
	}
	UserCache = filepath.Join(UserCache, notation)

	// set PathManager
	// TODO(JeyJeyGao): The user/system directory priority may change later
	// (https://github.com/notaryproject/notation/issues/203)
	Path = &PathManager{
		ConfigFS: NewUnionDirFS(
			NewRootedFS(UserConfig, nil),
			NewRootedFS(SystemConfig, nil),
		),
		CacheFS: NewUnionDirFS(
			NewRootedFS(UserCache, nil),
		),
		LibexecFS: NewUnionDirFS(
			NewRootedFS(UserLibexec, nil),
			NewRootedFS(SystemLibexec, nil),
		),
	}
}
