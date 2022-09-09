package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// save stores the cfg struct to file
func save(filePath string, cfg interface{}) error {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	file, err := os.Create(filePath)
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
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	return json.NewDecoder(file).Decode(cfg)
}
