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
