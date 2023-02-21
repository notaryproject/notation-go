package config

import (
	"reflect"
	"testing"

	"github.com/notaryproject/notation-go/dir"
)

var sampleConfig = &Config{
	InsecureRegistries: []string{
		"registry.wabbit-networks.io",
	},
	SignatureFormat: "jws",
}

func TestLoadFile(t *testing.T) {
	dir.UserConfigDir = "./testdata/valid"
	got, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error. err = %v", err)
	}

	if !reflect.DeepEqual(got, sampleConfig) {
		t.Errorf("loadFile() = %v, want %v", got, sampleConfig)
	}
}

func TestSaveFile(t *testing.T) {
	root := t.TempDir()
	dir.UserConfigDir = root
	sampleConfig.Save()
	config, err := LoadConfig()
	if err != nil {
		t.Fatal("Load config file from temp dir failed")
	}
	if !reflect.DeepEqual(sampleConfig, config) {
		t.Fatal("save config file failed.")
	}
}
