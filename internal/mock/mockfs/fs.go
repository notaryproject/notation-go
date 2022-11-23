package mockfs

import (
	"io/fs"
	"path/filepath"

	"github.com/notaryproject/notation-go/dir"
)

type sysFSMock struct {
	fs.FS
	root string
}

// SysPath returns the system path of the FS.
func (s sysFSMock) SysPath(items ...string) (string, error) {
	pathItems := []string{s.root}
	pathItems = append(pathItems, items...)
	return filepath.Join(pathItems...), nil
}

// NewSysFSMock returns a SysFS mock of the given FS.
func NewSysFSMock(fsys fs.FS) dir.SysFS {
	return sysFSMock{
		FS:   fsys,
		root: ""}
}

// NewSysFSWithRootMock returns a SysFS mock of the given fs and
// a root directory
func NewSysFSWithRootMock(fsys fs.FS, root string) dir.SysFS {
	return sysFSMock{
		FS:   fsys,
		root: root}
}
