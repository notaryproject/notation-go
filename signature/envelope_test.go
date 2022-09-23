package signature

import (
	"errors"
	"testing"

	"github.com/notaryproject/notation-core-go/signature/jws"
)

const invalidMediaType = "invalid"

func checkErrorEqual(expected, got error) bool {
	if expected == nil && got == nil {
		return true
	}
	if expected != nil && got != nil {
		return expected.Error() == got.Error()
	}
	return false
}

func TestValidateEnvelopeMediaType(t *testing.T) {
	tests := []struct {
		name        string
		mediaType   string
		expectedErr error
	}{
		{
			name:        "jws signature media type",
			mediaType:   jws.MediaTypeEnvelope,
			expectedErr: nil,
		},
		{
			name:        "invalid media type",
			mediaType:   invalidMediaType,
			expectedErr: errors.New("invalid envelope media type"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateEnvelopeMediaType(tt.mediaType); !checkErrorEqual(tt.expectedErr, err) {
				t.Fatalf("expected validate envelope media type err: %v, got: %v", tt.expectedErr, err)
			}
		})
	}
}
