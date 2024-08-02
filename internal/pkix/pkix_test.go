package pkix

import "testing"

func TestParseDistinguishedName(t *testing.T) {
	// Test cases
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid DN",
			input:   "C=US,ST=California,O=Notary Project",
			wantErr: false,
		},
		{
			name:    "valid DN with State alias",
			input:   "C=US,S=California,O=Notary Project",
			wantErr: false,
		},
		{
			name:    "invalid DN",
			input:   "C=US,ST=California",
			wantErr: true,
		},
		{
			name:    "invalid DN without State",
			input:   "C=US,O=Notary Project",
			wantErr: true,
		},
	}

	// Run tests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseDistinguishedName(tt.input)
			if tt.wantErr != (err != nil) {
				t.Errorf("ParseDistinguishedName() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

}
