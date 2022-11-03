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

func (s sysFSMock) SysPath(items ...string) (string, error) {
	pathItems := []string{s.root}
	pathItems = append(pathItems, items...)
	return filepath.Join(pathItems...), nil
}

func NewSysFSMock(fsys fs.FS, root string) dir.SysFS {
	return sysFSMock{
		FS:   fsys,
		root: root}
}
