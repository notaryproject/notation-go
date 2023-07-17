// Package config provides the ability to load and save config.json and
// signingkeys.json.
package config

import (
	"errors"
	"io/fs"
	"strings"

	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/internal/file"
)

// Config reflects the config.json file.
// Specification: https://github.com/notaryproject/notation/pull/76
type Config struct {
	InsecureRegistries []string          `json:"insecureRegistries"`
	CredentialsStore   string            `json:"credsStore,omitempty"`
	CredentialHelpers  map[string]string `json:"credHelpers,omitempty"`
	SignatureFormat    string            `json:"signatureFormat,omitempty"`
}

// cachedConfig is the in-memory copy of the config.json file.
var cachedConfig *Config

// Save stores the config to file
func (c *Config) Save() error {
	path, err := dir.ConfigFS().SysPath(dir.PathConfigFile)
	if err != nil {
		return err
	}
	return file.Save(path, c)
}

// IsRegistryInsecure returns true if given registry is configured to use http
// for communication
func (c *Config) IsRegistryInsecure(target string) bool {
	for _, registry := range c.InsecureRegistries {
		if strings.EqualFold(registry, target) {
			return true
		}
	}
	return false
}

// LoadFromCache returns the in-memory copy of config.json and
// reads the config from file, if not found.
func LoadFromCache() (*Config, error) {
	if cachedConfig != nil {
		return cachedConfig, nil
	}

	return Load()
}

// Load reads the config from file or return a default config if not found.
func Load() (*Config, error) {
	var config Config

	err := file.Load(dir.PathConfigFile, &config)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}

		config = Config{}
	}

	// update cache with latest read
	cachedConfig = &config
	return cachedConfig, nil
}
