package signingkeys

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/notaryproject/notation-core-go/testhelper"
	"github.com/notaryproject/notation-go/dir"
)

var sampleSigningKeysInfo = SigningKeys{
	Default: Ptr("wabbit-networks"),
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

func TestLoad(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		dir.UserConfigDir = "../testdata/valid"
		got, err := Load()
		if err != nil {
			t.Errorf("LoadSigningKeysInfo() error = \"%v\"", err)
			return
		}

		if !reflect.DeepEqual(sampleSigningKeysInfo.Default, got.Default) {
			t.Fatal("signingKeysInfo test failed.")
		}

		if !reflect.DeepEqual(sampleSigningKeysInfo.Keys, got.Keys) {
			t.Fatal("signingKeysInfo test failed.")
		}
	})

	t.Run("DuplicateKeys", func(t *testing.T) {
		expectedErr := "malformed signingkeys.json: multiple keys with name 'wabbit-networks' found"
		dir.UserConfigDir = "../testdata/malformed-duplicate"
		_, err := Load()
		if err == nil || err.Error() != expectedErr {
			t.Errorf("LoadSigningKeysInfo() error expected = \"%v\" but found = \"%v\"", expectedErr, err)
		}
	})

	t.Run("InvalidDefault", func(t *testing.T) {
		expectedErr := "malformed signingkeys.json: default key 'missing-default' not found"
		dir.UserConfigDir = "../testdata/malformed-invalid-default"
		_, err := Load()
		if err == nil || err.Error() != expectedErr {
			t.Errorf("LoadSigningKeysInfo() error expected = \"%v\" but found = \"%v\"", expectedErr, err)
		}
	})

	t.Run("signingkeys.json without read permission", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("skipping test on Windows")
		}
		dir.UserConfigDir = "../testdata/valid_signingkeys"
		defer func() error {
			// restore the permission
			return os.Chmod(filepath.Join(dir.UserConfigDir, "signingkeys.json"), 0644)
		}()

		// forbid reading the file
		if err := os.Chmod(filepath.Join(dir.UserConfigDir, "signingkeys.json"), 0000); err != nil {
			t.Error(err)
		}
		_, err := Load()
		if !strings.Contains(err.Error(), "permission denied") {
			t.Error("should error with permission denied")
		}
	})
}

func TestSaveSigningKeys(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		root := t.TempDir()
		dir.UserConfigDir = root
		sampleSigningKeysInfo.Save()
		info, err := Load()
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

	t.Run("ValidWithoutDefault", func(t *testing.T) {
		root := t.TempDir()
		dir.UserConfigDir = root
		sampleSigningKeysInfoNoDefault := deepCopySigningKeys(sampleSigningKeysInfo)
		sampleSigningKeysInfoNoDefault.Default = nil
		sampleSigningKeysInfoNoDefault.Save()
		info, err := Load()
		if err != nil {
			t.Fatal("Load signingkeys.json from temp dir failed.")
		}

		if !reflect.DeepEqual(sampleSigningKeysInfoNoDefault.Default, info.Default) {
			t.Fatal("Save signingkeys.json failed.")
		}

		if !reflect.DeepEqual(sampleSigningKeysInfoNoDefault.Keys, info.Keys) {
			t.Fatal("Save signingkeys.json failed.")
		}
	})

	t.Run("DuplicateKeys", func(t *testing.T) {
		expectedErr := "malformed signingkeys.json: multiple keys with name 'import.acme-rockets' found"
		dir.UserConfigDir = t.TempDir()
		duplicateKeySignKeysInfo := deepCopySigningKeys(sampleSigningKeysInfo)
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
		}
	})

	t.Run("EmptyKeyName", func(t *testing.T) {
		expectedErr := "malformed signingkeys.json: key name cannot be empty"
		dir.UserConfigDir = t.TempDir()
		emptyKeyNameSignKeysInfo := deepCopySigningKeys(sampleSigningKeysInfo)
		emptyKeyNameSignKeysInfo.Keys[0].Name = ""

		err := emptyKeyNameSignKeysInfo.Save()
		if err == nil || err.Error() != expectedErr {
			t.Errorf("Save signingkeys.json failed, error expected = \"%v\" but found = \"%v\"", expectedErr, err)
		}
	})

	t.Run("InvalidDefault", func(t *testing.T) {
		expectedErr := "malformed signingkeys.json: default key 'missing-default' not found"
		dir.UserConfigDir = t.TempDir()
		invalidDefaultSignKeysInfo := deepCopySigningKeys(sampleSigningKeysInfo)
		invalidDefaultSignKeysInfo.Default = Ptr("missing-default")
		err := invalidDefaultSignKeysInfo.Save()
		if err == nil || err.Error() != expectedErr {
			t.Errorf("Save signingkeys.json failed, error expected = \"%v\" but found = \"%v\"", expectedErr, err)
		}

		expectedErr = "malformed signingkeys.json: default key name cannot be empty"
		invalidDefaultSignKeysInfo.Default = Ptr("")
		err = invalidDefaultSignKeysInfo.Save()
		if err == nil || err.Error() != expectedErr {
			t.Errorf("Save signingkeys.json failed, error expected = \"%v\" but found = \"%v\"", expectedErr, err)
		}
	})
}

func TestAdd(t *testing.T) {
	certPath, keyPath := createTempCertKey(t)
	t.Run("WithDefault", func(t *testing.T) {
		testSigningKeys := deepCopySigningKeys(sampleSigningKeysInfo)
		expectedTestKeyName := "name1"

		if err := testSigningKeys.Add(expectedTestKeyName, keyPath, certPath, true); err != nil {
			t.Errorf("Add() failed with err= %v", err)
		}

		expectedSigningKeys := append(deepCopySigningKeys(sampleSigningKeysInfo).Keys, KeySuite{
			Name: expectedTestKeyName,
			X509KeyPair: &X509KeyPair{
				KeyPath:         keyPath,
				CertificatePath: certPath,
			},
		})

		if expectedTestKeyName != *testSigningKeys.Default {
			t.Error("Add() failed, incorrect default key")
		}
		if !reflect.DeepEqual(testSigningKeys.Keys, expectedSigningKeys) {
			t.Error("Add() failed, KeySuite mismatch")
		}
	})

	t.Run("WithoutDefault", func(t *testing.T) {
		dir.UserConfigDir = t.TempDir()

		testSigningKeys := deepCopySigningKeys(sampleSigningKeysInfo)
		expectedTestKeyName := "name2"
		certPath, keyPath := createTempCertKey(t)
		if err := testSigningKeys.Add(expectedTestKeyName, keyPath, certPath, false); err != nil {
			t.Errorf("Add() failed with err= %v", err)
		}

		expectedSigningKeys := append(deepCopySigningKeys(sampleSigningKeysInfo).Keys, KeySuite{
			Name: expectedTestKeyName,
			X509KeyPair: &X509KeyPair{
				KeyPath:         keyPath,
				CertificatePath: certPath,
			},
		})

		if *sampleSigningKeysInfo.Default != *testSigningKeys.Default {
			t.Error("Add() failed, default key changed")
		}
		if !reflect.DeepEqual(testSigningKeys.Keys, expectedSigningKeys) {
			t.Error("Add() failed, KeySuite mismatch")
		}
	})

	t.Run("InvalidCertKeyLocation", func(t *testing.T) {
		err := sampleSigningKeysInfo.Add("name1", "invalid", "invalid", true)
		if err == nil {
			t.Error("expected Add() to fail for invalid cert and key location")
		}
	})

	t.Run("InvalidName", func(t *testing.T) {
		err := sampleSigningKeysInfo.Add("", "invalid", "invalid", true)
		if err == nil {
			t.Error("expected Add() to fail for empty key name")
		}
	})

	t.Run("InvalidName", func(t *testing.T) {
		err := sampleSigningKeysInfo.Add("", "invalid", "invalid", true)
		if err == nil {
			t.Error("expected Add() to fail for empty key name")
		}
	})

	t.Run("DuplicateKey", func(t *testing.T) {
		err := sampleSigningKeysInfo.Add(sampleSigningKeysInfo.Keys[0].Name, "invalid", "invalid", true)
		if err == nil {
			t.Error("expected Add() to fail for duplicate name")
		}
	})
}

func TestPluginAdd(t *testing.T) {
	config := map[string]string{"key1": "value1"}
	name := "name1"
	id := "pluginId1"
	pluginName := "pluginName1"

	t.Run("InvalidCertKeyLocation", func(t *testing.T) {
		err := sampleSigningKeysInfo.Add("name1", "invalid", "invalid", true)
		if err == nil {
			t.Error("expected AddPlugin() to fail for invalid cert and key location")
		}
	})

	t.Run("InvalidName", func(t *testing.T) {
		err := sampleSigningKeysInfo.AddPlugin(context.Background(), "", id, pluginName, config, true)
		if err == nil {
			t.Error("expected AddPlugin() to fail for empty key name")
		}
	})

	t.Run("InvalidId", func(t *testing.T) {
		err := sampleSigningKeysInfo.AddPlugin(context.Background(), name, "", pluginName, config, true)
		if err == nil {
			t.Error("expected AddPlugin() to fail for empty key name")
		}
	})

	t.Run("InvalidPluginName", func(t *testing.T) {
		err := sampleSigningKeysInfo.AddPlugin(context.Background(), name, id, "", config, true)
		if err == nil {
			t.Error("AddPlugin AddPlugin() to fail for empty plugin name")
		}
	})
}

func TestGet(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		key, err := sampleSigningKeysInfo.Get("external-key")
		if err != nil {
			t.Errorf("Get() failed with error= %v", err)
		}

		if !reflect.DeepEqual(key, sampleSigningKeysInfo.Keys[2]) {
			t.Errorf("Get() returned %v but expected %v", key, sampleSigningKeysInfo.Keys[2])
		}
	})

	t.Run("NonExistent", func(t *testing.T) {
		if _, err := sampleSigningKeysInfo.Get("nonExistent"); err == nil {
			t.Error("expected Get() to fail for nonExistent key name")
		}
	})

	t.Run("InvalidName", func(t *testing.T) {
		if _, err := sampleSigningKeysInfo.Get(""); err == nil {
			t.Error("expected Get() to fail for invalid key name")
		}
	})
}

func TestGetDefault(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		key, err := sampleSigningKeysInfo.GetDefault()
		if err != nil {
			t.Errorf("GetDefault() failed with error= %v", err)
		}

		if !reflect.DeepEqual(key.Name, *sampleSigningKeysInfo.Default) {
			t.Errorf("GetDefault() returned %s but expected %s", key.Name, *sampleSigningKeysInfo.Default)
		}
	})

	t.Run("NoDefault", func(t *testing.T) {
		testSigningKeysInfo := deepCopySigningKeys(sampleSigningKeysInfo)
		testSigningKeysInfo.Default = nil
		if _, err := testSigningKeysInfo.GetDefault(); err == nil {
			t.Error("GetDefault Get() to fail there is no defualt key")
		}
	})
}

func TestUpdateDefault(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		testSigningKeysInfo := deepCopySigningKeys(sampleSigningKeysInfo)
		newDefault := sampleSigningKeysInfo.Keys[1].Name
		err := testSigningKeysInfo.UpdateDefault(newDefault)
		if err != nil {
			t.Errorf("UpdateDefault() failed with error= %v", err)
		}

		if !reflect.DeepEqual(newDefault, *testSigningKeysInfo.Default) {
			t.Errorf("UpdateDefault() didn't update default key")
		}
	})

	t.Run("NonExistent", func(t *testing.T) {
		if err := sampleSigningKeysInfo.UpdateDefault("nonExistent"); err == nil {
			t.Error("expected Get() to fail for nonExistent key name")
		}
	})

	t.Run("InvalidName", func(t *testing.T) {
		if err := sampleSigningKeysInfo.UpdateDefault(""); err == nil {
			t.Error("expected Get() to fail for invalid key name")
		}
	})
}

func TestRemove(t *testing.T) {
	testKeyName := "wabbit-networks"
	testSigningKeysInfo := deepCopySigningKeys(sampleSigningKeysInfo)
	t.Run("Valid", func(t *testing.T) {
		keys, err := testSigningKeysInfo.Remove(testKeyName)
		if err != nil {
			t.Errorf("testSigningKeysInfo() failed with error= %v", err)
		}

		if _, err := testSigningKeysInfo.Get(testKeyName); err == nil {
			t.Error("Delete() filed to delete key")
		}

		if keys[0] != testKeyName {
			t.Error("Delete() deleted key name mismatch")
		}
	})

	t.Run("NonExistent", func(t *testing.T) {
		if _, err := testSigningKeysInfo.Remove(testKeyName); err == nil {
			t.Error("expected Get() to fail for nonExistent key name")
		}
	})

	t.Run("InvalidName", func(t *testing.T) {
		if _, err := testSigningKeysInfo.Remove(""); err == nil {
			t.Error("expected Get() to fail for invalid key name")
		}
	})
}

func TestResolveKey(t *testing.T) {
	defer func(oldDir string) {
		dir.UserConfigDir = oldDir
	}(dir.UserConfigDir)

	t.Run("valid e2e key", func(t *testing.T) {
		dir.UserConfigDir = "../testdata/valid_signingkeys"
		sKeys, _ := Load()
		keySuite, err := sKeys.Resolve("e2e")
		if err != nil {
			t.Fatal(err)
		}
		if keySuite.Name != "e2e" {
			t.Error("key name is not correct.")
		}
	})

	t.Run("key name is empty (using default key)", func(t *testing.T) {
		dir.UserConfigDir = "../testdata/valid_signingkeys"
		sKeys, _ := Load()
		keySuite, err := sKeys.Resolve("")
		if err != nil {
			t.Fatal(err)
		}
		if keySuite.Name != "e2e" {
			t.Error("key name is not correct.")
		}
	})
}

func deepCopySigningKeys(keys SigningKeys) SigningKeys {
	cpyKeys := make([]KeySuite, len(sampleSigningKeysInfo.Keys))
	copy(cpyKeys, keys.Keys)
	cpyDefault := *keys.Default
	cpySignKeys := keys
	cpySignKeys.Default = &cpyDefault
	cpySignKeys.Keys = cpyKeys
	return cpySignKeys
}

func Ptr[T any](v T) *T {
	return &v
}

func createTempCertKey(t *testing.T) (string, string) {
	certTuple := testhelper.GetRSARootCertificate()
	certPath := filepath.Join(t.TempDir(), "cert.tmp")
	certData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certTuple.Cert.Raw})
	if err := os.WriteFile(certPath, certData, 0600); err != nil {
		panic(err)
	}
	keyPath := filepath.Join(t.TempDir(), "key.tmp")
	keyBytes, _ := x509.MarshalPKCS8PrivateKey(certTuple.PrivateKey)
	keyData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	if err := os.WriteFile(keyPath, keyData, 0600); err != nil {
		panic(err)
	}
	return certPath, keyPath
}
