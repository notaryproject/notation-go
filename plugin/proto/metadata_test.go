// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proto

import (
	"testing"

	"github.com/notaryproject/notation-plugin-framework-go/plugin"
)

func TestGetMetadataResponse_HasCapability(t *testing.T) {
	type args struct {
		capability plugin.Capability
	}
	tests := []struct {
		name string
		m    *plugin.GetMetadataResponse
		args args
		want bool
	}{
		{"empty capabilities", &plugin.GetMetadataResponse{}, args{"cap"}, false},
		{"other capabilities", &plugin.GetMetadataResponse{Capabilities: []plugin.Capability{"foo", "baz"}}, args{"cap"}, false},
		{"empty target capability", &plugin.GetMetadataResponse{Capabilities: []plugin.Capability{"foo", "baz"}}, args{""}, true},
		{"found", &plugin.GetMetadataResponse{Capabilities: []plugin.Capability{"foo", "baz"}}, args{"baz"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasCapability(tt.m, tt.args.capability); got != tt.want {
				t.Errorf("GetMetadataResponse.HasCapability() = %v, want %v", got, tt.want)
			}
		})
	}
}
