package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/notaryproject/notation-go/dir"
)

var (
	// ConfigPath is the path for config.json
	ConfigPath string
	// SigningKeysPath is the path for signingkeys.json
	SigningKeysPath string

	// configInfo is the information of config.json
	configInfo *ConfigFile
	configOnce sync.Once

	// signingKeysInfo is the information of signingkeys.json
	signingKeysInfo     *SigningKeys
	signingKeysInfoOnce sync.Once
)

func init() {
	ConfigPath = dir.Path.Config()
	SigningKeysPath = dir.Path.SigningKeyConfig()

}

// Configuration is a interface to manage notation config
type Configuration interface {
	Save() error
}

// Save stores the config to file
func Save(filePath string, config interface{}) error {
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
	return encoder.Encode(config)
}

// Load reads the config from file
func Load(filePath string, config interface{}) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	return json.NewDecoder(file).Decode(config)
}
