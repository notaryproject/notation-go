package file

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"github.com/notaryproject/notation-go/dir"
)

// IsValidFileName checks if a file name is cross-platform compatible
func IsValidFileName(fileName string) bool {
	return regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`).MatchString(fileName)
}

// Save stores the cfg struct to file
func Save(filePath string, cfg interface{}) error {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	file, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")
	return encoder.Encode(cfg)
}

// Load reads file, parses json and stores in cfg struct
func Load(filePath string, cfg interface{}) error {
	path, err := dir.ConfigFS().SysPath(filePath)
	if err != nil {
		return err
	}

	// throw error if path is a directory or is a symlink or does not exist.
	fileInfo, err := os.Lstat(path)
	if err != nil {
		return err
	}
	mode := fileInfo.Mode()
	if mode.IsDir() || mode&fs.ModeSymlink != 0 {
		return fmt.Errorf("%q is not a regular file (symlinks are not supported)", path)
	}

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return json.NewDecoder(file).Decode(cfg)
}
