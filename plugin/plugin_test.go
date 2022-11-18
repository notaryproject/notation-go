package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"testing"

	"github.com/notaryproject/notation-go/plugin/proto"
)

func TestGetMetadata(t *testing.T) {
	t.Run("plugin error is in invalid json format", func(t *testing.T) {
		exitErr := errors.New("unknown error")
		stderr := []byte("{}")
		wantErr := proto.RequestError{
			Code: proto.ErrorCodeGeneric,
			Err:  fmt.Errorf("response is not in JSON format. error: %v stderr: %v", exitErr, stderr)}
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
			Err:  fmt.Errorf("response is not in JSON format. error: %v stderr: %v", exitErr, stderr)}
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
