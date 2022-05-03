package plugin

import (
	"testing"
)

func TestGenerateSignatureRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		req     *GenerateSignatureRequest
		wantErr bool
	}{
		{"nil", nil, true},
		{"empty", &GenerateSignatureRequest{"", "", "", ""}, true},
		{"missing version", &GenerateSignatureRequest{"", "2", "3", ""}, true},
		{"missing key name", &GenerateSignatureRequest{"1", "", "3", ""}, true},
		{"missing key id", &GenerateSignatureRequest{"1", "2", "", ""}, true},
		{"valid", &GenerateSignatureRequest{"1", "2", "3", ""}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.req.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("GenerateSignatureRequest.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGenerateEnvelopeRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		req     *GenerateEnvelopeRequest
		wantErr bool
	}{
		{"nil", nil, true},
		{"empty", &GenerateEnvelopeRequest{"", "", "", "", "", ""}, true},
		{"missing version", &GenerateEnvelopeRequest{"", "2", "3", "4", "5", ""}, true},
		{"missing key name", &GenerateEnvelopeRequest{"1", "", "3", "4", "5", ""}, true},
		{"missing key id", &GenerateEnvelopeRequest{"1", "2", "", "4", "5", ""}, true},
		{"missing type", &GenerateEnvelopeRequest{"1", "2", "3", "", "5", ""}, true},
		{"missing envelop", &GenerateEnvelopeRequest{"1", "2", "3", "4", "", ""}, true},
		{"valid", &GenerateEnvelopeRequest{"1", "2", "3", "4", "5", ""}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.req.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("GenerateEnvelopeRequest.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
