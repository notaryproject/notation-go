package config

import (
	"errors"
	"io/fs"

	"github.com/notaryproject/notation-go/dir"
)

// CertificateReference is a named file path.
type CertificateReference struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// Is checks whether the given name is equal with the Name variable
func (c CertificateReference) Is(name string) bool {
	return c.Name == name
}

// Config reflects the config.json file.
// Specification: https://github.com/notaryproject/notation/pull/76
type Config struct {
	VerificationCertificates VerificationCertificates `json:"verificationCerts"`
	InsecureRegistries       []string                 `json:"insecureRegistries"`
	CredentialsStore         string                   `json:"credsStore,omitempty"`
	CredentialHelpers        map[string]string        `json:"credHelpers,omitempty"`
}

// VerificationCertificates is a collection of public certs used for verification.
type VerificationCertificates struct {
	Certificates []CertificateReference `json:"certs"`
}

// NewConfig creates a new config file
func NewConfig() *Config {
	return &Config{
		InsecureRegistries: []string{},
	}
}

// Save stores the config to file.
//
// if the `path` is an empty string, it uses built-in user level config directory.
func (c *Config) Save(path string) error {
	// set default path
	if path == "" {
		path = dir.Path.Config(dir.UserLevel)
	}
	return save(path, c)
}

// LoadConfig reads the config from file or return a default config if not found.
//
// if `path` is an empty string, it uses built-in config.json directory, including
// user level and system level.
func LoadConfig(path string) (*Config, error) {
	// set default path
	if path == "" {
		path = dir.Path.Config(dir.UnionLevel)
	}

	// load config
	var config Config
	err := load(path, &config)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return NewConfig(), nil
		}
		return nil, err
	}
	return &config, nil
}
