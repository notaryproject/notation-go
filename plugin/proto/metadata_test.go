package proto

import (
	"strconv"
	"testing"
)

func TestGetMetadataResponse_Validate(t *testing.T) {
	tests := []struct {
		m       *GetMetadataResponse
		wantErr bool
	}{
		{&GetMetadataResponse{}, true},
		{&GetMetadataResponse{Name: "name"}, true},
		{&GetMetadataResponse{Name: "name", Description: "friendly"}, true},
		{&GetMetadataResponse{Name: "name", Description: "friendly", Version: "1"}, true},
		{&GetMetadataResponse{Name: "name", Description: "friendly", Version: "1", URL: "example.com"}, true},
		{&GetMetadataResponse{Name: "name", Description: "friendly", Version: "1", URL: "example.com", Capabilities: []Capability{"cap"}}, true},
		{&GetMetadataResponse{Name: "name", Description: "friendly", Version: "1", URL: "example.com", SupportedContractVersions: []string{"1"}}, true},
		{&GetMetadataResponse{Name: "name", Description: "friendly", Version: "1", URL: "example.com", SupportedContractVersions: []string{"1"}, Capabilities: []Capability{"cap"}}, false},
	}
	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			if err := tt.m.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("GetMetadataResponse.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetMetadataResponse_HasCapability(t *testing.T) {
	type args struct {
		capability Capability
	}
	tests := []struct {
		name string
		m    *GetMetadataResponse
		args args
		want bool
	}{
		{"empty capabilities", &GetMetadataResponse{}, args{"cap"}, false},
		{"other capabilities", &GetMetadataResponse{Capabilities: []Capability{"foo", "baz"}}, args{"cap"}, false},
		{"empty target capability", &GetMetadataResponse{Capabilities: []Capability{"foo", "baz"}}, args{""}, true},
		{"found", &GetMetadataResponse{Capabilities: []Capability{"foo", "baz"}}, args{"baz"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.m.HasCapability(tt.args.capability); got != tt.want {
				t.Errorf("GetMetadataResponse.HasCapability() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetMetadataResponse_SupportsContract(t *testing.T) {
	type args struct {
		major string
	}
	tests := []struct {
		name string
		m    *GetMetadataResponse
		args args
		want bool
	}{
		{"empty versions", &GetMetadataResponse{}, args{"2"}, false},
		{"other versions", &GetMetadataResponse{SupportedContractVersions: []string{"1", "2"}}, args{"3"}, false},
		{"found", &GetMetadataResponse{SupportedContractVersions: []string{"1", "2"}}, args{"2"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.m.SupportsContract(tt.args.major); got != tt.want {
				t.Errorf("GetMetadataResponse.SupportsContract() = %v, want %v", got, tt.want)
			}
		})
	}
}
