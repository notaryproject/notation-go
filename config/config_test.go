package config

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/notaryproject/notation-go/dir"
)

const (
	configPath      = "./testdata/config.json"
	nonexistentPath = "./testdata/nonexistent.json"
)

var sampleConfig = &Config{
	VerificationCertificates: VerificationCertificates{
		Certificates: []CertificateReference{
			{
				Name: "wabbit-networks",
				Path: "/home/demo/.config/notation/certificate/wabbit-networks.crt",
			},
			{
				Name: "import.acme-rockets",
				Path: "/home/demo/.config/notation/certificate/import.acme-rockets.crt",
			},
		},
	},
	InsecureRegistries: []string{
		"registry.wabbit-networks.io",
	},
	EnvelopeType: "jws",
}

func TestLoadFile(t *testing.T) {
	t.Cleanup(func() {
		// restore path
		ConfigPath = dir.Path.Config()
	})
	type args struct {
		filePath string
	}
	tests := []struct {
		name    string
		args    args
		want    *Config
		wantErr bool
	}{
		{
			name:    "load config file",
			args:    args{filePath: configPath},
			want:    sampleConfig,
			wantErr: false,
		},
		{
			name:    "load default config file",
			args:    args{filePath: nonexistentPath},
			want:    NewConfig(),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ConfigPath = tt.args.filePath
			got, err := LoadConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("loadFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("loadFile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSaveFile(t *testing.T) {
	t.Cleanup(func() {
		// restore path
		ConfigPath = dir.Path.Config()
	})
	root := t.TempDir()
	ConfigPath = filepath.Join(root, "config.json")
	sampleConfig.Save()
	config, err := LoadConfig()
	if err != nil {
		t.Fatal("Load config file from temp dir failed")
	}
	if !reflect.DeepEqual(sampleConfig, config) {
		t.Fatal("save config file failed.")
	}
}
