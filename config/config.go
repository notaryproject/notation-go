package config

import (
	"errors"
	"io/fs"

	"github.com/notaryproject/notation-go/dir"
)

// Config reflects the config.json file.
// Specification: https://github.com/notaryproject/notation/pull/76
type Config struct {
	InsecureRegistries []string          `json:"insecureRegistries"`
	CredentialsStore   string            `json:"credsStore,omitempty"`
	CredentialHelpers  map[string]string `json:"credHelpers,omitempty"`
	// SignatureFormat defines the signature envelope type for signing
	SignatureFormat string `json:"signatureFormat,omitempty"`
}

// NewConfig creates a new config file
func NewConfig() *Config {
	return &Config{}
}

// Save stores the config to file
func (c *Config) Save() error {
	path, err := dir.ConfigFS().SysPath(dir.PathConfigFile)
	if err != nil {
		return err
	}
	return save(path, c)
}

// LoadConfig reads the config from file or return a default config if not found.
func LoadConfig() (*Config, error) {
	var config Config

	err := load(dir.PathConfigFile, &config)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return NewConfig(), nil
		}
		return nil, err
	}
	return &config, nil
}
