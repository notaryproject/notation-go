package config

import (
	"reflect"
	"testing"

	"github.com/notaryproject/notation-go/dir"
)

const (
	signingKeysPath = "./testdata/signingkeys.json"
)

var sampleSigningKeysInfo = &SigningKeys{
	Default: "wabbit-networks",
	Keys: []KeySuite{
		{
			Name: "wabbit-networks",
			X509KeyPair: &X509KeyPair{
				KeyPath:         "/home/demo/.config/notation/localkeys/wabbit-networks.key",
				CertificatePath: "/home/demo/.config/notation/localkeys/wabbit-networks.crt",
			},
		},
		{
			Name: "import.acme-rockets",
			X509KeyPair: &X509KeyPair{
				KeyPath:         "/home/demo/.config/notation/localkeys/import.acme-rockets.key",
				CertificatePath: "/home/demo/.config/notation/localkeys/import.acme-rockets.crt",
			},
		},
		{
			Name: "external-key",
			ExternalKey: &ExternalKey{

				ID:         "id1",
				PluginName: "pluginX",
				PluginConfig: map[string]string{
					"key": "value",
				},
			},
		},
	},
}

func TestLoadSigningKeysInfo(t *testing.T) {
	dir.UserConfigDir = "./testdata"
	got, err := LoadSigningKeys()
	if err != nil {
		t.Errorf("LoadSigningKeysInfo() error = %v", err)
		return
	}
	if !reflect.DeepEqual(sampleSigningKeysInfo, got) {
		t.Fatal("singingKeysInfo test failed.")
	}

}

func TestSaveSigningKeys(t *testing.T) {
	root := t.TempDir()
	dir.UserConfigDir = root
	sampleSigningKeysInfo.Save()
	info, err := LoadSigningKeys()
	if err != nil {
		t.Fatal("Load signingkeys.json from temp dir failed.")
	}
	if !reflect.DeepEqual(sampleSigningKeysInfo, info) {
		t.Fatal("Save signingkeys.json failed.")
	}
}
