package mock_fs

import (
	"io/fs"
	"path/filepath"

	"github.com/notaryproject/notation-go/dir"
)

type sysFSMock struct {
	fs.FS
	root string
}

func (s sysFSMock) SysPath(name string) (string, error) {
	return filepath.Join(s.root, name), nil
}

func NewSysFSMock(fsys fs.FS, root string) dir.SysFS {
	return sysFSMock{
		FS:   fsys,
		root: root}
}
