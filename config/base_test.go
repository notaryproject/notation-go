package config

import (
	"fmt"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/notaryproject/notation-go/dir"
)

func TestLoadOnce(t *testing.T) {
	t.Cleanup(func() {
		ConfigPath = dir.Path.Config()
		SigningKeysPath = dir.Path.SigningKeyConfig()
	})
	ConfigPath = configPath
	SigningKeysPath = signingKeysPath
	cfg, err := LoadOnce()
	if err != nil {
		t.Fatal("call LoadOnce() failed.")
	}
	if reflect.DeepEqual(Configuration{
		Config:      *sampleConfig,
		SigningKeys: *sampleSigningKeysInfo,
	}, cfg) {
		t.Fatal("call LoadOnce() failed.")
	}
}

func TestOnce(t *testing.T) {
	t.Cleanup(func() {
		ConfigPath = dir.Path.Config()
		SigningKeysPath = dir.Path.SigningKeyConfig()
	})
	root := t.TempDir()
	ConfigPath = filepath.Join(root, dir.ConfigFile)
	SigningKeysPath = filepath.Join(root, dir.SigningKeysFile)
	cfg := Configuration{
		Config:      *sampleConfig,
		SigningKeys: *sampleSigningKeysInfo,
	}
	// save config in temp directory
	err := cfg.Save()
	if err != nil {
		t.Fatal(fmt.Sprintf("call Save() failed. error: %v", err))
	}
	// load saved file
	savedCfg, err := LoadOnce()
	if err != nil {
		t.Fatal("call LoadOnce() failed.")
	}
	if reflect.DeepEqual(cfg, savedCfg) {
		t.Fatal("call Save() failed.")
	}
}
