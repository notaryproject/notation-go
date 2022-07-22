package config

import (
	"errors"
	"io/fs"
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

// ConfigFile reflects the config file.
// Specification: https://github.com/notaryproject/notation/pull/76
type ConfigFile struct {
	VerificationCertificates VerificationCertificates `json:"verificationCerts"`
	InsecureRegistries       []string                 `json:"insecureRegistries"`
}

// VerificationCertificates is a collection of public certs used for verification.
type VerificationCertificates struct {
	Certificates []CertificateReference `json:"certs"`
}

// NewConfig creates a new config file
func NewConfig() *ConfigFile {
	return &ConfigFile{
		InsecureRegistries: []string{},
	}
}

// Save stores the config to file
func (f *ConfigFile) Save() error {
	return Save(ConfigPath, f)
}

// LoadConfig reads the config from file or return a default config if not found.
func LoadConfig() (*ConfigFile, error) {
	var config ConfigFile
	err := Load(ConfigPath, &config)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return NewConfig(), nil
		}
		return nil, err
	}
	return &config, nil
}

// LoadConfigOnce returns the previously read config file.
// If previous config file does not exists, it reads the config from file
// or return a default config if not found.
// The returned config is only suitable for read only scenarios for short-lived processes.
func LoadConfigOnce() (*ConfigFile, error) {
	var err error
	configOnce.Do(func() {
		configInfo, err = LoadConfig()
	})
	return configInfo, err
}
