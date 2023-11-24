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

package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/notaryproject/notation-go/plugin/proto"
)

func TestGetMetadata(t *testing.T) {
	t.Run("plugin error is in invalid json format", func(t *testing.T) {
		exitErr := errors.New("unknown error")
		stderr := []byte("sad")
		wantErr := proto.RequestError{
			Code: proto.ErrorCodeGeneric,
			Err:  fmt.Errorf("response is not in JSON format. error: %v, stderr: %s", exitErr, string(stderr))}
		plugin := CLIPlugin{}
		executor = testCommander{stdout: nil, stderr: stderr, err: exitErr}
		_, err := plugin.GetMetadata(context.Background(), &proto.GetMetadataRequest{})
		if !errors.Is(err, wantErr) {
			t.Fatalf("should error. got err = %v, want %v", err, wantErr)
		}
	})

	t.Run("plugin error is a valid json", func(t *testing.T) {
		stderr := []byte("{\"errorCode\":\"ACCESS_DENIED\"}")
		pluginErr := errors.New("plugin errors")
		wantErr := proto.RequestError{Code: proto.ErrorCodeAccessDenied}

		plugin := CLIPlugin{}
		executor = testCommander{stdout: nil, stderr: stderr, err: pluginErr}
		_, err := plugin.GetMetadata(context.Background(), &proto.GetMetadataRequest{})
		if !errors.Is(err, wantErr) {
			t.Fatalf("should error. got err = %v, want %v", err, wantErr)
		}
	})

	t.Run("plugin cause system error", func(t *testing.T) {
		exitErr := errors.New("system error")
		stderr := []byte("")
		wantErr := proto.RequestError{
			Code: proto.ErrorCodeGeneric,
			Err:  fmt.Errorf("response is not in JSON format. error: %v, stderr: %s", exitErr, string(stderr))}
		plugin := CLIPlugin{}
		executor = testCommander{stdout: nil, stderr: stderr, err: exitErr}
		_, err := plugin.GetMetadata(context.Background(), &proto.GetMetadataRequest{})
		if !errors.Is(err, wantErr) {
			t.Fatalf("should error. got err = %v, want %v", err, wantErr)
		}
	})

}

func TestDescribeKey(t *testing.T) {
	t.Run("DescribeKey test", func(t *testing.T) {
		keyResp := proto.DescribeKeyResponse{KeyID: "1", KeySpec: "RSA-4096"}
		output, err := json.Marshal(keyResp)
		if err != nil {
			t.Fatal("should not error.")
		}
		executor = testCommander{stdout: output, err: nil}

		plugin := CLIPlugin{}
		resp, err := plugin.DescribeKey(context.Background(), &proto.DescribeKeyRequest{})
		if err != nil {
			t.Fatalf("should not error. got err = %v", err)
		}
		if reflect.DeepEqual(resp, keyResp) {
			t.Fatalf("DescribeKey() error. got: %+v, want: %+v", resp, keyResp)
		}
	})
}

func TestGenerateSignature(t *testing.T) {
	t.Run("GenerateSignature test", func(t *testing.T) {
		keyResp := proto.GenerateSignatureResponse{
			KeyID:            "1",
			Signature:        []byte("xxxxx"),
			SigningAlgorithm: "ECDSA-SHA-256",
			CertificateChain: [][]byte{{121, 132, 30, 42}},
		}
		output, err := json.Marshal(keyResp)
		if err != nil {
			t.Fatal("should not error.")
		}
		executor = testCommander{stdout: output, err: nil}

		plugin := CLIPlugin{}
		resp, err := plugin.GenerateSignature(context.Background(), &proto.GenerateSignatureRequest{})
		if err != nil {
			t.Fatalf("should not error. got err = %v", err)
		}
		if reflect.DeepEqual(resp, keyResp) {
			t.Fatalf("GenerateSignature() error. got: %+v, want: %+v", resp, keyResp)
		}
	})
}

func TestGenerateEnvelope(t *testing.T) {
	t.Run("GenerateEnvelope test", func(t *testing.T) {
		keyResp := proto.GenerateEnvelopeResponse{
			SignatureEnvelope:     []byte("{}"),
			SignatureEnvelopeType: "jws",
			Annotations:           map[string]string{},
		}
		output, err := json.Marshal(keyResp)
		if err != nil {
			t.Fatal("should not error.")
		}
		executor = testCommander{stdout: output, err: nil}

		plugin := CLIPlugin{}
		resp, err := plugin.GenerateEnvelope(context.Background(), &proto.GenerateEnvelopeRequest{})
		if err != nil {
			t.Fatalf("should not error. got err = %v", err)
		}
		if reflect.DeepEqual(resp, keyResp) {
			t.Fatalf("GenerateEnvelope() error. got: %+v, want: %+v", resp, keyResp)
		}
	})
}

func TestVerifySignature(t *testing.T) {
	t.Run("VerifySignature test", func(t *testing.T) {
		keyResp := proto.VerifySignatureResponse{
			VerificationResults: map[proto.Capability]*proto.VerificationResult{},
			ProcessedAttributes: []interface{}{"attr1"},
		}
		output, err := json.Marshal(keyResp)
		if err != nil {
			t.Fatal("should not error.")
		}
		executor = testCommander{stdout: output, err: nil}

		plugin := CLIPlugin{}
		resp, err := plugin.VerifySignature(context.Background(), &proto.VerifySignatureRequest{})
		if err != nil {
			t.Fatalf("should not error. got err = %v", err)
		}
		if reflect.DeepEqual(resp, keyResp) {
			t.Fatalf("VerifySignature() error. got: %+v, want: %+v", resp, keyResp)
		}
	})
}

func TestValidateMetadata(t *testing.T) {
	tests := []struct {
		m       *proto.GetMetadataResponse
		wantErr bool
	}{
		{&proto.GetMetadataResponse{}, true},
		{&proto.GetMetadataResponse{Name: "name"}, true},
		{&proto.GetMetadataResponse{Name: "name", Description: "friendly"}, true},
		{&proto.GetMetadataResponse{Name: "name", Description: "friendly", Version: "1"}, true},
		{&proto.GetMetadataResponse{Name: "name", Description: "friendly", Version: "1", URL: "example.com"}, true},
		{&proto.GetMetadataResponse{Name: "name", Description: "friendly", Version: "1", URL: "example.com", Capabilities: []proto.Capability{"cap"}}, true},
		{&proto.GetMetadataResponse{Name: "name", Description: "friendly", Version: "1", URL: "example.com", SupportedContractVersions: []string{"1.0"}}, true},
		{&proto.GetMetadataResponse{Name: "name", Description: "friendly", Version: "1", URL: "example.com", SupportedContractVersions: []string{"1.0"}, Capabilities: []proto.Capability{"cap"}}, false},
	}
	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			if err := validate(tt.m); (err != nil) != tt.wantErr {
				t.Errorf("GetMetadataResponse.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewCLIPlugin_PathError(t *testing.T) {
	ctx := context.Background()
	t.Run("plugin directory exists without executable.", func(t *testing.T) {
		p, err := NewCLIPlugin(ctx, "emptyplugin", "./testdata/plugins/emptyplugin/notation-emptyplugin")
		if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("NewCLIPlugin() error = %v, want %v", err, os.ErrNotExist)
		}
		if p != nil {
			t.Errorf("NewCLIPlugin() plugin = %v, want nil", p)
		}
	})

	t.Run("plugin is not a regular file", func(t *testing.T) {
		p, err := NewCLIPlugin(ctx, "badplugin", "./testdata/plugins/badplugin/notation-badplugin")
		if !errors.Is(err, ErrNotRegularFile) {
			t.Errorf("NewCLIPlugin() error = %v, want %v", err, ErrNotRegularFile)
		}
		if p != nil {
			t.Errorf("NewCLIPlugin() plugin = %v, want nil", p)
		}
	})
}

func TestNewCLIPlugin_ValidError(t *testing.T) {
	ctx := context.Background()
	p, err := NewCLIPlugin(ctx, "foo", "./testdata/plugins/foo/notation-foo")
	if err != nil {
		t.Fatal("should no error.")
	}
	t.Run("command no response", func(t *testing.T) {
		executor = testCommander{}
		_, err := p.GetMetadata(ctx, &proto.GetMetadataRequest{})
		if !strings.Contains(err.Error(), ErrNotCompliant.Error()) {
			t.Fatal("should fail the operation.")
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		executor = testCommander{stdout: []byte("content")}
		_, err := p.GetMetadata(ctx, &proto.GetMetadataRequest{})
		if !strings.Contains(err.Error(), ErrNotCompliant.Error()) {
			t.Fatal("should fail the operation.")
		}
	})

	t.Run("invalid metadata name", func(t *testing.T) {
		executor = testCommander{stdout: metadataJSON(invalidMetadataName)}
		_, err := p.GetMetadata(ctx, &proto.GetMetadataRequest{})
		if !strings.Contains(err.Error(), "executable name must be") {
			t.Fatal("should fail the operation.")
		}
	})

	t.Run("invalid metadata content", func(t *testing.T) {
		executor = testCommander{stdout: metadataJSON(proto.GetMetadataResponse{Name: "foo"})}
		_, err := p.GetMetadata(ctx, &proto.GetMetadataRequest{})
		if !strings.Contains(err.Error(), "invalid metadata") {
			t.Fatal("should fail the operation.")
		}
	})

	t.Run("valid", func(t *testing.T) {
		executor = testCommander{stdout: metadataJSON(validMetadata)}
		_, err := p.GetMetadata(ctx, &proto.GetMetadataRequest{})
		if err != nil {
			t.Fatalf("should valid. got err = %v", err)
		}
		metadata, err := p.GetMetadata(context.Background(), &proto.GetMetadataRequest{})
		if err != nil {
			t.Fatalf("should valid. got err = %v", err)
		}
		if !reflect.DeepEqual(metadata, &validMetadata) {
			t.Fatalf("should be equal. got metadata = %+v, want %+v", metadata, validMetadata)
		}
	})

	t.Run("invalid contract version", func(t *testing.T) {
		executor = testCommander{stdout: metadataJSON(invalidContractVersionMetadata)}
		_, err := p.GetMetadata(ctx, &proto.GetMetadataRequest{})
		if err == nil {
			t.Fatal("should have an invalid contract version error")
		}
	})
}

func TestExtractPluginNameFromExecutableFileName(t *testing.T) {
	pluginName, err := ExtractPluginNameFromFileName("notation-my-plugin")
	if err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}
	if pluginName != "my-plugin" {
		t.Fatalf("expected plugin name my-plugin, but got %s", pluginName)
	}

	pluginName, err = ExtractPluginNameFromFileName("notation-my-plugin.exe")
	if err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}
	if pluginName != "my-plugin" {
		t.Fatalf("expected plugin name my-plugin, but got %s", pluginName)
	}

	_, err = ExtractPluginNameFromFileName("myPlugin")
	expectedErrorMsg := "invalid plugin executable file name. Plugin file name requires format notation-{plugin-name}, but got myPlugin"
	if err == nil || err.Error() != expectedErrorMsg {
		t.Fatalf("expected %s, got %v", expectedErrorMsg, err)
	}

	_, err = ExtractPluginNameFromFileName("my-plugin")
	expectedErrorMsg = "invalid plugin executable file name. Plugin file name requires format notation-{plugin-name}, but got my-plugin"
	if err == nil || err.Error() != expectedErrorMsg {
		t.Fatalf("expected %s, got %v", expectedErrorMsg, err)
	}
}

func TestValidatePluginFileExtensionAgainstOS(t *testing.T) {
	if runtime.GOOS == "windows" {
		err := validatePluginFileExtensionAgainstOS("notation-foo.exe", "foo")
		if err != nil {
			t.Fatalf("expecting nil error, but got %s", err)
		}

		err = validatePluginFileExtensionAgainstOS("notation-foo", "foo")
		expectedErrorMsg := "invalid plugin file name extension. Expecting file notation-foo.exe, but got notation-foo"
		if err == nil || err.Error() != expectedErrorMsg {
			t.Fatalf("expecting error %s, but got %v", expectedErrorMsg, err)
		}
		return
	}
	err := validatePluginFileExtensionAgainstOS("notation-foo", "foo")
	if err != nil {
		t.Fatalf("expecting nil error, but got %s", err)
	}

	err = validatePluginFileExtensionAgainstOS("notation-foo.exe", "foo")
	expectedErrorMsg := "invalid plugin file name extension. Expecting file notation-foo, but got notation-foo.exe"
	if err == nil || err.Error() != expectedErrorMsg {
		t.Fatalf("expecting error %s, but got %v", expectedErrorMsg, err)
	}
}
