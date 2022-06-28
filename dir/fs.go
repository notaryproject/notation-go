package dir

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
)

// UnionDirFsIFace is a simple union directory file system interface
type UnionDirFsIFace interface {
	fs.ReadDirFS
	GetPath(elem ...string) (string, error)
}

// NewUnionDirFS is a virtual file system for merging multiple directories with priority
//
// dirs contains the union directories and the previous one has higher priority
func NewUnionDirFS(dirs ...string) UnionDirFS {
	rootedDirs := []RootedFS{}
	for _, dir := range dirs {
		rootedDirs = append(rootedDirs, RootedFS{os.DirFS(dir), dir})
	}
	return UnionDirFS{Dirs: rootedDirs}
}

// RootedFS is io.FS implementation used in New.
// root is the root of the file system tree passed to os.DirFS.
type RootedFS struct {
	fs.FS
	Root string
}

// UnionDirFS is a simple union directory file system
//
// it unions multiple directory to be one directory with priority based on the order of Dirs
type UnionDirFS struct {
	Dirs []RootedFS
}

// Open implements fs.FS interface
//
// traverse all union directories and return the first existing file
func (u UnionDirFS) Open(name string) (fs.File, error) {
	for _, dir := range u.Dirs {
		f, err := dir.Open(name)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			} else {
				return nil, err
			}
		}
		return f, nil
	}
	return nil, fs.ErrNotExist
}

// Path returns the path of the named file or directory under the FS
//
// if path exists, it returns the first existing path in union directories (dirs)
// if path doesn't exist, it returns fs.ErrNotExist error
func (u UnionDirFS) GetPath(elem ...string) (string, error) {
	pathSuffix := path.Join(elem...)
	for _, dir := range u.Dirs {
		file, err := dir.Open(pathSuffix)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			} else {
				return "", err
			}
		}
		defer file.Close()
		// got the first existing file path and break
		return filepath.Join(dir.Root, pathSuffix), nil
	}
	// return the path with current OS separator
	return "", fs.ErrNotExist
}

// ReadDir implements the ReadDirFile interface
//
// traverse all union directories and return all existing DirEntries
func (u UnionDirFS) ReadDir(name string) ([]fs.DirEntry, error) {
	isVisited := make(map[string]bool)
	var newEntries []fs.DirEntry
	// traverse multiple union directories
	for _, dir := range u.Dirs {
		f, err := dir.Open(name)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			} else {
				return nil, err
			}
		}
		defer f.Close()

		// try to get entries
		file, ok := f.(fs.ReadDirFile)
		if !ok {
			return nil, &fs.PathError{Op: "readdir", Err: errors.New("not implemented")}
		}
		entries, err := file.ReadDir(-1)
		if err != nil {
			return nil, err
		}

		// skip repeated entry name
		// it is possible that multiple union directories have the entries with the same name
		for _, entry := range entries {
			if _, ok := isVisited[entry.Name()]; !ok {
				isVisited[entry.Name()] = true
				newEntries = append(newEntries, entry)
			}
		}
	}
	return newEntries, nil
}

// PluginFS returns the UnionDirFS for notation plugins
func PluginFS(dirs ...string) UnionDirFS {
	dirs = append(dirs, filepath.Join(userLibexec, "plugins"))
	dirs = append(dirs, filepath.Join(systemLibexec, "plugins"))
	return NewUnionDirFS(dirs...)
}
