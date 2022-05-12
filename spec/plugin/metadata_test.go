package plugin

import (
	"strconv"
	"testing"
)

func TestMetadata_Validate(t *testing.T) {
	tests := []struct {
		m       *Metadata
		wantErr bool
	}{
		{&Metadata{}, true},
		{&Metadata{Name: "name"}, true},
		{&Metadata{Name: "name", Description: "friendly"}, true},
		{&Metadata{Name: "name", Description: "friendly", Version: "1"}, true},
		{&Metadata{Name: "name", Description: "friendly", Version: "1", URL: "example.com"}, true},
		{&Metadata{Name: "name", Description: "friendly", Version: "1", URL: "example.com", Capabilities: []Capability{"cap"}}, true},
		{&Metadata{Name: "name", Description: "friendly", Version: "1", URL: "example.com", SupportedContractVersions: []string{"1"}}, true},
		{&Metadata{Name: "name", Description: "friendly", Version: "1", URL: "example.com", SupportedContractVersions: []string{"1"}, Capabilities: []Capability{"cap"}}, false},
	}
	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			if err := tt.m.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Metadata.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMetadata_HasCapability(t *testing.T) {
	type args struct {
		capability Capability
	}
	tests := []struct {
		name string
		m    *Metadata
		args args
		want bool
	}{
		{"empty capabilities", &Metadata{}, args{"cap"}, false},
		{"other capabilities", &Metadata{Capabilities: []Capability{"foo", "baz"}}, args{"cap"}, false},
		{"empty target capability", &Metadata{Capabilities: []Capability{"foo", "baz"}}, args{""}, true},
		{"found", &Metadata{Capabilities: []Capability{"foo", "baz"}}, args{"baz"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.m.HasCapability(tt.args.capability); got != tt.want {
				t.Errorf("Metadata.HasCapability() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMetadata_SupportsContract(t *testing.T) {
	type args struct {
		major string
	}
	tests := []struct {
		name string
		m    *Metadata
		args args
		want bool
	}{
		{"empty versions", &Metadata{}, args{"2"}, false},
		{"other versions", &Metadata{SupportedContractVersions: []string{"1", "2"}}, args{"3"}, false},
		{"found", &Metadata{SupportedContractVersions: []string{"1", "2"}}, args{"2"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.m.SupportsContract(tt.args.major); got != tt.want {
				t.Errorf("Metadata.SupportsContract() = %v, want %v", got, tt.want)
			}
		})
	}
}
