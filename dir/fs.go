package dir

import (
	"io/fs"
	"os"
	"path/filepath"
)

// SysFS is virtual file system interface that support fs.FS and SysPath method.
type SysFS interface {
	fs.FS

	// SysPath returns the real system path of the given name in the SysFS.
	SysPath(name string) (string, error)
}

type sysFS struct {
	fs.FS
	root string
}

// SysPath returns the real system path of the given name in the SysFS.
func (s sysFS) SysPath(name string) (string, error) {
	return filepath.Join(s.root, name), nil
}

// NewSysFS returns the SysFS for the given roots directories.
//
// Support one root directory for rc.1, and may support union directories FS
// after rc.1.
func NewSysFS(roots ...string) SysFS {
	if len(roots) == 0 {
		return nil
	}
	return sysFS{
		FS:   os.DirFS(roots[0]),
		root: roots[0]}
}

// ConfigFS is the config SysFS
func ConfigFS() SysFS {
	return NewSysFS(UserConfigDir)
}

// PluginFS is the plugin SysFS
func PluginFS() SysFS {
	return NewSysFS(filepath.Join(UserLibexecDir, "plugins"))
}
