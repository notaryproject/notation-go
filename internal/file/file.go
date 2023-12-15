// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package file

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ErrNotRegularFile is returned when the file is not an regular file.
var ErrNotRegularFile = errors.New("not regular file")

// ErrNotDirectory is returned when the path is not a directory.
var ErrNotDirectory = errors.New("not directory")

// IsValidFileName checks if a file name is cross-platform compatible
func IsValidFileName(fileName string) bool {
	return regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`).MatchString(fileName)
}

// CopyToDir copies the src file to dst dir. Existing file will be overwritten.
// src file permission is preserved.
func CopyToDir(src, dst string) error {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !sourceFileStat.Mode().IsRegular() {
		return ErrNotRegularFile
	}
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()
	if err := os.MkdirAll(dst, 0777); err != nil {
		return err
	}
	dstFile := filepath.Join(dst, filepath.Base(src))
	destination, err := os.Create(dstFile)
	if err != nil {
		return err
	}
	defer destination.Close()
	err = destination.Chmod(sourceFileStat.Mode())
	if err != nil {
		return err
	}
	_, err = io.Copy(destination, source)
	return err
}

// CopyDirToDir copies contents in src dir to dst dir. Only regular files are
// copied. Existing files will be overwritten.
func CopyDirToDir(src, dst string) error {
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !fi.Mode().IsDir() {
		return ErrNotDirectory
	}
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// skip sub-directories
		if d.IsDir() && d.Name() != filepath.Base(path) {
			return fs.SkipDir
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		// only copy regular files
		if info.Mode().IsRegular() {
			return CopyToDir(path, dst)
		}
		return nil
	})
}

// TrimFileExtension returns the file name without extension.
//
// For example,
//
// when input is xyz.exe, output is xyz
//
// when input is xyz.tar.gz, output is xyz.tar
func TrimFileExtension(fileName string) string {
	return strings.TrimSuffix(fileName, filepath.Ext(fileName))
}
