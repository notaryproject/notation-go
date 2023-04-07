package config

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/notaryproject/notation-go/dir"
)

// save stores the cfg struct to file
func save(filePath string, cfg interface{}) error {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	// #nosec: Paths a hardcoded
	file, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")
	return encoder.Encode(cfg)
}

// load reads file, parses json and stores in cfg struct
func load(filePath string, cfg interface{}) error {
	file, err := dir.ConfigFS().Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	return json.NewDecoder(file).Decode(cfg)
}
