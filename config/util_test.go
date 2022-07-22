package config

import (
	"reflect"
	"testing"

	"github.com/notaryproject/notation-go/dir"
)

func TestResolveKey(t *testing.T) {
	t.Cleanup(func() {
		// restore path
		SigningKeysPath = dir.Path.SigningKeyConfig()
	})
	SigningKeysPath = signingKeysPath
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		args    args
		want    KeySuite
		wantErr bool
	}{
		{
			name:    "resolve valid key",
			args:    args{name: "import.acme-rockets"},
			want:    sampleSigningKeysInfo.Keys[1],
			wantErr: false,
		},
		{
			name:    "resolve default key",
			args:    args{name: ""},
			want:    sampleSigningKeysInfo.Keys[0],
			wantErr: false,
		},
		{
			name:    "resolve nonexistent key",
			args:    args{name: "x"},
			want:    KeySuite{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveKey(tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("ResolveKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ResolveKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsRegistryInsecure(t *testing.T) {
	t.Cleanup(func() {
		ConfigPath = configPath
	})
	ConfigPath = configPath
	type args struct {
		target string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "insecure exist",
			args: args{target: "registry.wabbit-networks.io"},
			want: true,
		},
		{
			name: "insecure doesn't exist",
			args: args{target: "x"},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRegistryInsecure(tt.args.target); got != tt.want {
				t.Errorf("IsRegistryInsecure() = %v, want %v", got, tt.want)
			}
		})
	}
}
