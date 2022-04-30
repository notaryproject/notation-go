package plugin

import (
	"errors"
	"io"
	"os"
	"testing"
)

var validMetadata = &Metadata{
	Name: "foo", Description: "friendly", Version: "1", URL: "example.com",
	SupportedContractVersions: []string{"1"}, Capabilities: []Capability{"other"},
}

func withCapability(cap Capability) *Metadata {
	m := *validMetadata
	m.Capabilities = append(m.Capabilities, cap)
	return &m
}

func runFunc(resp interface{}, err error) RunFunc {
	return func(command Command, req interface{}) (interface{}, error) {
		return resp, err
	}
}

func TestRunWithFlagSet(t *testing.T) {
	signArgs := append([]string{string(new(GenerateSignatureRequest).Command())}, (&GenerateSignatureRequest{"1", "2", "3"}).Args()...)
	envelopArgs := append([]string{string(new(GenerateEnvelopeRequest).Command())}, (&GenerateEnvelopeRequest{"1", "2", "3", "4", "5"}).Args()...)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer w.Close()
		io.Copy(io.Discard, r)
	}()
	stdout = w
	stderr = w
	type args struct {
		metadata *Metadata
		fn       RunFunc
		args     []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"empty args", args{validMetadata, runFunc(nil, nil), nil}, true},
		{"unknown command", args{validMetadata, runFunc(nil, nil), []string{"not-a-command"}}, true},
		{"metadata", args{validMetadata, runFunc(nil, nil), []string{string(CommandGetMetadata)}}, false},
		{"no sign capability", args{validMetadata, runFunc(nil, nil), signArgs}, true},
		{"invalid sign args", args{withCapability(CapabilitySignatureGenerator), runFunc(nil, nil), []string{string(CommandGenerateSignature)}}, true},
		{"nil response", args{withCapability(CapabilitySignatureGenerator), runFunc(nil, nil), signArgs}, true},
		{"error response", args{withCapability(CapabilitySignatureGenerator), runFunc(nil, errors.New("failed")), signArgs}, true},
		{"invalid response", args{withCapability(CapabilitySignatureGenerator), runFunc(1, nil), signArgs}, true},
		{"valid sign", args{withCapability(CapabilitySignatureGenerator), runFunc(&GenerateSignatureResponse{}, nil), signArgs}, false},
		{"valid envelop", args{withCapability(CapabilityEnvelopeGenerator), runFunc(&GenerateEnvelopeResponse{}, nil), envelopArgs}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RunWithFlagSet(nil, tt.args.metadata, tt.args.fn, tt.args.args...)
			if (err != nil) != tt.wantErr {
				t.Fatalf("RunWithFlagSet() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRun(t *testing.T) {
	err := Run(validMetadata, runFunc(nil, nil))
	if err == nil {
		t.Errorf("Run() error = %v, wantErr true", err)
	}
}
