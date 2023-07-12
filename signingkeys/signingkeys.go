package signingkeys

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"

	"github.com/notaryproject/notation-go/internal/file"
	"github.com/notaryproject/notation-go/internal/slices"
	"github.com/notaryproject/notation-go/log"
	"github.com/notaryproject/notation-go/plugin"

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

var errorKeyNameEmpty = errors.New("key name cannot be empty")
var errKeyNotFound = errors.New("signing key not found")

// cachedSigningKey is the in-memory copy of the signingkeys.json file.
var cachedSigningKey *SigningKeys

// SigningKeys reflects the signingkeys.json file.
type SigningKeys struct {
	Default *string    `json:"default,omitempty"`
	Keys    []KeySuite `json:"keys"`
}

// Add adds new signing key
func (s *SigningKeys) Add(name, keyPath, certPath string, markDefault bool) error {
	if name == "" {
		return errorKeyNameEmpty
	}
	_, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return err
	}

	ks := KeySuite{
		Name: name,
		X509KeyPair: &X509KeyPair{
			KeyPath:         keyPath,
			CertificatePath: certPath,
		},
	}
	return s.add(ks, markDefault)
}

// AddPlugin adds new plugin based signing key
func (s *SigningKeys) AddPlugin(ctx context.Context, keyName, id, pluginName string, pluginConfig map[string]string, markDefault bool) error {
	logger := log.GetLogger(ctx)
	logger.Debugf("Adding key with name %v and plugin name %v", keyName, pluginName)

	if keyName == "" {
		return errorKeyNameEmpty
	}

	if id == "" {
		return errors.New("missing key id")
	}

	if pluginName == "" {
		return errors.New("plugin name cannot be empty")
	}

	mgr := plugin.NewCLIManager(dir.PluginFS())
	_, err := mgr.Get(ctx, pluginName)
	if err != nil {
		return err
	}

	ks := KeySuite{
		Name: keyName,
		ExternalKey: &ExternalKey{
			ID:           id,
			PluginName:   pluginName,
			PluginConfig: pluginConfig,
		},
	}

	if err = s.add(ks, markDefault); err != nil {
		logger.Error("Failed to add key with error: %v", err)
		return err
	}
	logger.Debugf("Added key with name %s - {%+v}", keyName, ks)
	return nil
}

// Get returns signing key for the given name
func (s *SigningKeys) Get(keyName string) (KeySuite, error) {
	if keyName == "" {
		return KeySuite{}, errorKeyNameEmpty
	}

	idx := slices.IndexIsser(s.Keys, keyName)
	if idx < 0 {
		return KeySuite{}, errKeyNotFound
	}

	return s.Keys[idx], nil
}

// GetDefault returns default signing key
func (s *SigningKeys) GetDefault() (KeySuite, error) {
	if s.Default == nil {
		return KeySuite{}, errors.New("default signing key not set." +
			" Please set default signing key or specify a key name")
	}

	return s.Get(*s.Default)
}

func (s *SigningKeys) Resolve(name string) (KeySuite, error) {
	// if name is empty, look for default signing key
	if name == "" {
		return s.GetDefault()
	}

	return s.Get(name)
}

// Remove deletes given signing keys and returns a slice of deleted key names
func (s *SigningKeys) Remove(keyName ...string) ([]string, error) {
	var deletedNames []string
	for _, name := range keyName {
		if name == "" {
			return deletedNames, errorKeyNameEmpty
		}

		idx := slices.IndexIsser(s.Keys, name)
		if idx < 0 {
			return deletedNames, errors.New(name + ": not found")
		}
		s.Keys = slices.Delete(s.Keys, idx)
		deletedNames = append(deletedNames, name)
		if s.Default != nil && *s.Default == name {
			s.Default = nil
		}
	}
	return deletedNames, nil
}

// UpdateDefault updates default signing key
func (s *SigningKeys) UpdateDefault(keyName string) error {
	if keyName == "" {
		return errorKeyNameEmpty
	}

	if !slices.ContainsIsser(s.Keys, keyName) {
		return fmt.Errorf("key with name '%s' not found", keyName)
	}

	s.Default = &keyName
	return nil
}

// Save SigningKeys to signingkeys.json file
func (s *SigningKeys) Save() error {
	path, err := dir.ConfigFS().SysPath(dir.PathSigningKeys)
	if err != nil {
		return err
	}

	if err := validateKeys(s); err != nil {
		return err
	}

	return file.Save(path, s)
}

// LoadFromCache returns the cached signingkeys.json if present else
// reads the signingkeys.json file  and return a default config if not found.
func LoadFromCache() (*SigningKeys, error) {
	if cachedSigningKey != nil {
		return cachedSigningKey, nil
	}

	return Load()
}

// Load reads the signingkeys.json file
// or return a default config if not found.
func Load() (*SigningKeys, error) {
	var signingKeys SigningKeys
	err := file.Load(dir.PathSigningKeys, &signingKeys)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &SigningKeys{Keys: []KeySuite{}}, nil
		}
		return nil, err
	}

	if err := validateKeys(&signingKeys); err != nil {
		return nil, err
	}

	// update cache with latest read
	cachedSigningKey = &signingKeys

	return cachedSigningKey, nil
}

// LoadExecSave loads signing key, executes given function and
// then saves the signing key
func LoadExecSave(fn func(keys *SigningKeys) error) error {
	// core process
	signingKeys, err := Load()
	if err != nil {
		return err
	}

	if err := fn(signingKeys); err != nil {
		return err
	}

	return signingKeys.Save()
}

// Is checks whether the given name is equal with the Name variable
func (k KeySuite) Is(name string) bool {
	return k.Name == name
}

func (s *SigningKeys) add(key KeySuite, markDefault bool) error {
	if slices.ContainsIsser(s.Keys, key.Name) {
		return fmt.Errorf("signing key with name %q already exists", key.Name)
	}

	s.Keys = append(s.Keys, key)
	if markDefault {
		s.Default = &key.Name
	}

	return nil
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
