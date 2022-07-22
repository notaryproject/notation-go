package config

import (
	"errors"
	"io/fs"
)

// X509KeyPair contains the paths of a public/private key pair files.
type X509KeyPair struct {
	KeyPath         string `json:"keyPath,omitempty"`
	CertificatePath string `json:"certPath,omitempty"`
}

// ExternalKey contains the necessary information to delegate
// the signing operation to the named plugin.
type ExternalKey struct {
	ID           string            `json:"id,omitempty"`
	PluginName   string            `json:"pluginName,omitempty"`
	PluginConfig map[string]string `json:"pluginConfig,omitempty"`
}

// KeySuite is a named key suite.
type KeySuite struct {
	Name string `json:"name"`

	*X509KeyPair
	*ExternalKey
}

// Is checks whether the given name is equal with the Name variable
func (k KeySuite) Is(name string) bool {
	return k.Name == name
}

// SigningKeys is a collection of signing keys.
type SigningKeys struct {
	Default string     `json:"default"`
	Keys    []KeySuite `json:"keys"`
}

// Save config to file
func (s *SigningKeys) Save() error {
	return Save(SigningKeysPath, s)
}

// NewSigningKeys creates a new signingkeys config file
func NewSigningKeys() *SigningKeys {
	return &SigningKeys{Keys: []KeySuite{}}
}

// LoadSigningKeys reads the config from file
// or return a default config if not found.
func LoadSigningKeys() (*SigningKeys, error) {
	var config SigningKeys
	err := Load(SigningKeysPath, &config)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return NewSigningKeys(), nil
		}
		return nil, err
	}
	return &config, nil
}

// LoadSigningKeysOnce returns the previously read config file.
// If previous config file does not exists, it reads the config from file
// or return a default config if not found.
// The returned config is only suitable for read only scenarios for short-lived processes.
func LoadSigningKeysOnce() (*SigningKeys, error) {
	var err error
	signingKeysInfoOnce.Do(func() {
		signingKeysInfo, err = LoadSigningKeys()
	})
	return signingKeysInfo, err
}
