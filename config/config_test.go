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

func TestLoadNonExistedConfig(t *testing.T) {
	dir.UserConfigDir = "./testdata/non-existed"
	got, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error. err = %v", err)
	}

	if !reflect.DeepEqual(got, NewConfig()) {
		t.Errorf("loadFile() = %v, want %v", got, NewConfig())
	}
}
