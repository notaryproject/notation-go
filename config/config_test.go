package config

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
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
	dir.UserConfigDir = "../testdata/valid"
	got, err := Load()
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
	config, err := Load()
	if err != nil {
		t.Fatal("Load config file from temp dir failed")
	}
	if !reflect.DeepEqual(sampleConfig, config) {
		t.Fatal("save config file failed.")
	}
}

func TestIsRegistryInsecure(t *testing.T) {
	// for restore dir
	defer func(oldDir string) {
		dir.UserConfigDir = oldDir
	}(dir.UserConfigDir)
	// update config dir
	dir.UserConfigDir = "../testdata/valid"
	type args struct {
		target string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{name: "hit registry", args: args{target: "registry.wabbit-networks.io"}, want: true},
		{name: "miss registry", args: args{target: "reg2.io"}, want: false},
	}

	cfg, err := LoadFromCache()
	if err != nil {
		t.Fatalf("LoadFromCache() failed to load config with error: %v", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cfg.IsRegistryInsecure(tt.args.target); got != tt.want {
				t.Errorf("IsRegistryInsecure(%s) = %v, want %v", tt.args.target, got, tt.want)
			}
		})
	}

}

func TestIsRegistryInsecureMissingConfig(t *testing.T) {
	// update config dir
	dir.UserConfigDir = "./invalid"

	type args struct {
		target string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{name: "missing config", args: args{target: "reg1.io"}, want: false},
	}

	cfg, err := LoadFromCache()
	if err != nil {
		t.Fatalf("LoadFromCache() failed to load config with error: %v", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cfg.IsRegistryInsecure(tt.args.target); got != tt.want {
				t.Fatalf("IsRegistryInsecure() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsRegistryInsecureConfigPermissionError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping test on Windows")
	}
	configDir := "../testdata/valid"
	// for restore dir
	defer func(oldDir string) error {
		// restore permission
		dir.UserConfigDir = oldDir
		return os.Chmod(filepath.Join(configDir, "config.json"), 0644)
	}(dir.UserConfigDir)

	// update config dir
	dir.UserConfigDir = configDir

	// forbid reading the file
	if err := os.Chmod(filepath.Join(configDir, "config.json"), 0000); err != nil {
		t.Error(err)
	}

	cfg, err := LoadFromCache()
	if err != nil {
		t.Fatalf("LoadFromCache() failed to load config with error: %v", err)
	}
	if cfg.IsRegistryInsecure("reg1.io") {
		t.Fatalf("should false because of missing config.json read permission.")
	}
}
