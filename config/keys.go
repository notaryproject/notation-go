package config

import (
	"errors"
	"io/fs"

	"github.com/notaryproject/notation-go/dir"
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

// Is checks whether the given name is equal with the Name variable.
func (k KeySuite) Is(name string) bool {
	return k.Name == name
}

// SigningKeys reflects the signingkeys.json file.
type SigningKeys struct {
	Default string     `json:"default"`
	Keys    []KeySuite `json:"keys"`
}

// Save config to file.
//
// if `path` is not set, it uses build-in user level signingkey.json directory.
func (s *SigningKeys) Save(path ...string) error {
	if len(path) > 0 {
		return save(path[0], s)
	}
	return save(dir.Path.SigningKeyConfig(), s)
}

// NewSigningKeys creates a new signingkeys config file.
func NewSigningKeys() *SigningKeys {
	return &SigningKeys{Keys: []KeySuite{}}
}

// LoadSigningKeys reads the config from file
// or return a default config if not found.
//
// if `path` is not set, it uses build-in user level signingkey.json directory.
func LoadSigningKeys(path ...string) (*SigningKeys, error) {
	var (
		err    error
		config SigningKeys
	)
	if len(path) > 0 {
		err = load(path[0], &config)
	} else {
		err = load(dir.Path.SigningKeyConfig(), &config)
	}

	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return NewSigningKeys(), nil
		}
		return nil, err
	}
	return &config, nil
}
