package proto

import (
	"testing"
)

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
