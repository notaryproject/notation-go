package config

import (
	"errors"
	"fmt"
	"io/fs"

	"github.com/notaryproject/notation-go/dir"
	set "github.com/notaryproject/notation-go/internal/container"
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

// SigningKeys reflects the signingkeys.json file.
type SigningKeys struct {
	Default *string    `json:"default"`
	Keys    []KeySuite `json:"keys"`
}

// Save config to file
func (s *SigningKeys) Save() error {
	path, err := dir.ConfigFS().SysPath(dir.PathSigningKeys)
	if err != nil {
		return err
	}

	if err := validateKeys(s); err != nil {
		return err
	}

	return save(path, s)
}

// NewSigningKeys creates a new signingkeys config file
func NewSigningKeys() *SigningKeys {
	return &SigningKeys{Keys: []KeySuite{}}
}

// LoadSigningKeys reads the config from file
// or return a default config if not found.
func LoadSigningKeys() (*SigningKeys, error) {
	var config SigningKeys
	err := load(dir.PathSigningKeys, &config)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return NewSigningKeys(), nil
		}
		return nil, err
	}

	if err := validateKeys(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

func validateKeys(config *SigningKeys) error {
	keys := config.Keys
	uniqueKeyNames := set.NewWithSize[string](len(keys))
	for _, key := range keys {
		if len(key.Name) == 0 {
			return fmt.Errorf("malformed %s: key name cannot be empty", dir.PathSigningKeys)
		}
		if uniqueKeyNames.Contains(key.Name) {
			return fmt.Errorf("malformed %s: multiple keys with name '%s' found", dir.PathSigningKeys, key.Name)
		}
		uniqueKeyNames.Add(key.Name)
	}

	if config.Default != nil {
		defaultKey := *config.Default
		if len(defaultKey) == 0 {
			return fmt.Errorf("malformed %s: default key name cannot be empty", dir.PathSigningKeys)
		}

		if !uniqueKeyNames.Contains(defaultKey) {
		return fmt.Errorf("malformed %s: default key '%s' not found", dir.PathSigningKeys, defaultKey)
		}
	}

	return nil
}
