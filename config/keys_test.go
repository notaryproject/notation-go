package config

import (
	"reflect"
	"testing"

	"github.com/notaryproject/notation-go/dir"
)

var sampleSigningKeysInfo = SigningKeys{
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
	t.Run("Valid", func(t *testing.T) {
		dir.UserConfigDir = "./testdata/valid"
		got, err := LoadSigningKeys()
		if err != nil {
			t.Errorf("LoadSigningKeysInfo() error = \"%v\"", err)
			return
		}
		if !reflect.DeepEqual(sampleSigningKeysInfo, got) {
			t.Fatal("singingKeysInfo test failed.")
		}
	})

	t.Run("DuplicateKeys", func(t *testing.T) {
		expectedErr := "malformed signingkeys.json: multiple keys with name 'wabbit-networks' found"
		dir.UserConfigDir = "./testdata/malformed-duplicate"
		_, err := LoadSigningKeys()
		if err == nil || err.Error() != expectedErr {
			t.Errorf("LoadSigningKeysInfo() error expected = \"%v\" but found = \"%v\"", expectedErr, err)
		}
	})

	t.Run("InvalidDefault", func(t *testing.T) {
		expectedErr := "malformed signingkeys.json: default key 'missing-default' not found"
		dir.UserConfigDir = "./testdata/malformed-invalid-default"
		_, err := LoadSigningKeys()
		if err == nil || err.Error() != expectedErr {
			t.Errorf("LoadSigningKeysInfo() error expected = \"%v\" but found = \"%v\"", expectedErr, err)
		}
	})
}

func TestSaveSigningKeys(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		root := t.TempDir()
		dir.UserConfigDir = root
		sampleSigningKeysInfo.Save()
		info, err := LoadSigningKeys()
		if err != nil {
			t.Fatal("Load signingkeys.json from temp dir failed.")
		}

		if !reflect.DeepEqual(sampleSigningKeysInfo.Default, info.Default) {
			t.Fatal("Save signingkeys.json failed.")
		}

		if !reflect.DeepEqual(sampleSigningKeysInfo.Keys, info.Keys) {
			t.Fatal("Save signingkeys.json failed.")
		}
	})

	t.Run("DuplicateKeys", func(t *testing.T) {
		expectedErr := "malformed signingkeys.json: multiple keys with name 'import.acme-rockets' found"
		dir.UserConfigDir = t.TempDir()
		duplicateKeySignKeysInfo := sampleSigningKeysInfo
		duplicateKeySignKeysInfo.Keys = append(duplicateKeySignKeysInfo.Keys, KeySuite{
			Name: "import.acme-rockets",
			X509KeyPair: &X509KeyPair{
				KeyPath:         "/keypath",
				CertificatePath: "/CertificatePath",
			},
		})
		err := duplicateKeySignKeysInfo.Save()
		if err == nil || err.Error() != expectedErr {
			t.Errorf("Save signingkeys.json failed, error expected = \"%v\" but found = \"%v\"", expectedErr, err)
			return
		}
	})

	t.Run("InvalidDefault", func(t *testing.T) {
		expectedErr := "malformed signingkeys.json: default key 'missing-default' not found"
		dir.UserConfigDir = t.TempDir()
		invalidDefaultSignKeysInfo := sampleSigningKeysInfo
		invalidDefaultSignKeysInfo.Default = "missing-default"
		err := invalidDefaultSignKeysInfo.Save()
		if err == nil || err.Error() != expectedErr {
			t.Errorf("Save signingkeys.json failed, error expected = \"%v\" but found = \"%v\"", expectedErr, err)
			return
		}
	})
}
