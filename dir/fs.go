package dir

import (
	"io/fs"
	"os"
	"path/filepath"
)

// SysFS is virtual file system interface that support fs.FS and SysPath method.
type SysFS interface {
	fs.FS

	// SysPath returns the real system path of the given path items in the SysFS.
	SysPath(items ...string) (string, error)
}

type sysFS struct {
	fs.FS
	root string
}

// SysPath returns the real system path of the given name in the SysFS.
func (s sysFS) SysPath(items ...string) (string, error) {
	pathItems := []string{s.root}
	pathItems = append(pathItems, items...)
	return filepath.Join(pathItems...), nil
}

// NewSysFS returns the SysFS for the given root directory.
//
// Support one root directory for rc.1, and may support union directories FS
// after rc.1.
func NewSysFS(root string) SysFS {
	return sysFS{
		FS:   os.DirFS(root),
		root: root}
}

// ConfigFS is the config SysFS
func ConfigFS() SysFS {
	return NewSysFS(UserConfigDir)
}

// PluginFS is the plugin SysFS
func PluginFS() SysFS {
	return NewSysFS(filepath.Join(UserLibexecDir, PathPlugins))
}
