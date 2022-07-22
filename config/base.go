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
	configInfo     *Config
	configInfoOnce sync.Once

	// signingKeysInfo is the information of signingkeys.json
	signingKeysInfo     *SigningKeys
	signingKeysInfoOnce sync.Once
)

func init() {
	ConfigPath = dir.Path.Config()
	SigningKeysPath = dir.Path.SigningKeyConfig()
}

// Configuration is the main config struct of notation-go
type Configuration struct {
	Config
	SigningKeys
}

// Save stores sub-configurations to files
func (c *Configuration) Save() error {
	if err := c.Config.Save(); err != nil {
		return err
	}
	return c.SigningKeys.Save()
}

// LoadOnce returns the previously read config file.
// If previous config file does not exist, it reads the config from file
// or return a default config if not found.
// The returned config is only suitable for read only scenarios for short-lived processes.
func LoadOnce() (*Configuration, error) {
	configInfo, err := loadConfigOnce()
	if err != nil {
		return nil, err
	}
	signingKeysInfo, err := loadSigningKeysOnce()
	if err != nil {
		return nil, err
	}
	return &Configuration{
		Config:      *configInfo,
		SigningKeys: *signingKeysInfo,
	}, nil
}

// Save stores the cfg struct to file
func Save(filePath string, cfg interface{}) error {
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

// Load reads file, parses json and stores in cfg struct
func Load(filePath string, cfg interface{}) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	return json.NewDecoder(file).Decode(cfg)
}
