package config

import (
	"path/filepath"
	"reflect"
	"testing"
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
}

func TestLoadFile(t *testing.T) {
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
			got, err := LoadConfig(tt.args.filePath)
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
	root := t.TempDir()
	configPath := filepath.Join(root, "config.json")
	sampleConfig.Save(configPath)
	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal("Load config file from temp dir failed")
	}
	if !reflect.DeepEqual(sampleConfig, config) {
		t.Fatal("save config file failed.")
	}
}
