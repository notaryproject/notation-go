package dir

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
)

// RootedFS is a file system interface supporting for getting root path.
type RootedFS interface {
	fs.FS
	// Root returns the root path of the RootedFS
	Root() string
}

type rootedFS struct {
	fs.FS
	root string
}

// Root returns the root path of the rootedFS
func (r *rootedFS) Root() string {
	return r.root
}

// NewRootedFS create a rootedFS
//
// if fsys is nil, uses os.DirFS
func NewRootedFS(root string, fsys fs.FS) RootedFS {
	if fsys == nil {
		return &rootedFS{FS: os.DirFS(root), root: root}
	}
	return &rootedFS{FS: fsys, root: root}
}

// UnionDirFS is a simple union directory file system interface
type UnionDirFS interface {
	fs.ReadDirFS

	// GetPath returns the path of the named file or directory under the FS
	GetPath(elem ...string) (string, error)

	// ListAllPath returns all available paths of the named file or directory
	// under the FS
	ListAllPath(elem ...string) []string
}

// NewUnionDirFS create an unionDirFS by rootedFS
func NewUnionDirFS(rootedFsys ...RootedFS) UnionDirFS {
	return unionDirFS{Dirs: rootedFsys}
}

// unionDirFS is a simple union directory file system
//
// it unions multiple directory to be one directory with priority based on the
// order of Dirs
type unionDirFS struct {
	Dirs []RootedFS
}

// Open implements fs.FS interface
//
// traverse all union directories and return the first existing file
func (u unionDirFS) Open(name string) (fs.File, error) {
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
	return nil, &fs.PathError{Op: "open", Err: fs.ErrNotExist, Path: name}
}

// GetPath returns the path of the named file or directory under the FS
//
// if path exists, it returns the first existing path in union directories (dirs)
//
// if path doesn't exist, it returns the first possible path in the union directories
// for creating new file and a fs.ErrNotExist error.
func (u unionDirFS) GetPath(elem ...string) (string, error) {
	pathSuffix := path.Join(elem...)
	for _, dir := range u.Dirs {
		_, err := fs.Stat(dir, pathSuffix)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			} else {
				return "", err
			}
		}
		// got the first existing file path and break
		// return the path with current OS separator
		return filepath.Join(dir.Root(), pathSuffix), nil
	}
	// if the given path does not exist, return the first possible path in the
	// union directories for creating new file.
	var fallbackPath string
	if len(u.Dirs) == 0 {
		return "", &fs.PathError{
			Op:  "getpath",
			Err: errors.New("the union directory is empty"),
		}
	}
	fallbackPath = filepath.Join(u.Dirs[0].Root(), pathSuffix)
	return fallbackPath, &fs.PathError{
		Op:   "getpath",
		Err:  fs.ErrNotExist,
		Path: pathSuffix,
	}
}

// ListAllPath returns all available paths of the named file or directory under
// the unionDirFS
//
// if path doesn't exist, the result would be empty.
func (u unionDirFS) ListAllPath(elem ...string) []string {
	pathSuffix := path.Join(elem...)
	var paths []string
	for _, dir := range u.Dirs {
		_, err := fs.Stat(dir, pathSuffix)
		if err == nil {
			paths = append(paths, filepath.Join(dir.Root(), pathSuffix))
		}
	}
	return paths
}

// ReadDir implements the ReadDirFS interface
//
// traverse all union directories and return all existing DirEntries
func (u unionDirFS) ReadDir(name string) ([]fs.DirEntry, error) {
	isVisited := make(map[string]struct{})
	var newEntries []fs.DirEntry
	// traverse multiple union directories
	for _, dir := range u.Dirs {
		entries, err := fs.ReadDir(dir, name)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			} else {
				return nil, err
			}
		}
		// skip repeated entry name
		// it is possible that multiple union directories have the entries
		// with the same name
		for _, entry := range entries {
			if _, ok := isVisited[entry.Name()]; !ok {
				isVisited[entry.Name()] = struct{}{}
				newEntries = append(newEntries, entry)
			}
		}
	}
	return newEntries, nil
}

// PluginFS returns the UnionDirFS for notation plugins
// if dirs is set, use dirs as the directories for plugins
// if dirs is not set, use build-in directory structure for plugins
func PluginFS(dirs ...string) UnionDirFS {
	var rootedFsys []RootedFS
	if len(dirs) == 0 {
		dirs = append(dirs, filepath.Join(userLibexec, "plugins"))
		dirs = append(dirs, filepath.Join(systemLibexec, "plugins"))
	}
	for _, dir := range dirs {
		rootedFsys = append(rootedFsys, NewRootedFS(dir, nil))
	}
	return NewUnionDirFS(rootedFsys...)
}
