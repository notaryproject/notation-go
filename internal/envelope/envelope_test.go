package envelope

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/signature/cose"
	"github.com/notaryproject/notation-core-go/signature/jws"
	gcose "github.com/veraison/go-cose"
)

var (
	validCoseSignatureEnvelope []byte
	signaturePath              = filepath.FromSlash("../testdata/cose_signature.sig")
)

func init() {
	msg := gcose.Sign1Message{
		Headers:   gcose.NewSign1Message().Headers,
		Payload:   []byte("valid"),
		Signature: []byte("valid"),
	}
	validCoseSignatureEnvelope, _ = msg.MarshalCBOR()
}

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
			name:        "cose signature media type",
			mediaType:   cose.MediaTypeEnvelope,
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
			if err := validateEnvelopeMediaType(tt.mediaType); !checkErrorEqual(tt.expectedErr, err) {
				t.Fatalf("expected validate envelope media type err: %v, got: %v", tt.expectedErr, err)
			}
		})
	}
}

func TestValidatePayloadContentType(t *testing.T) {
	payload := &signature.Payload{
		ContentType: MediaTypePayloadV1,
	}
	err := ValidatePayloadContentType(payload)
	if !isErrEqual(nil, err) {
		t.Fatalf("ValidatePayloadContentType() expects error: %v, but got: %v.", nil, err)
	}

	payload = &signature.Payload{
		ContentType: "invalid",
	}
	err = ValidatePayloadContentType(payload)
	expect := errors.New("payload content type \"invalid\" not supported")
	if !isErrEqual(expect, err) {
		t.Fatalf("ValidatePayloadContentType() expects error: %v, but got: %v.", expect, err)
	}
}

func TestSigningTime(t *testing.T) {
	signature, err := os.ReadFile(signaturePath)
	if err != nil {
		t.Fatalf("failed to read signature: %v", err)
	}
	signatureMediaType := cose.MediaTypeEnvelope
	signingTime, err := SigningTime(signature, signatureMediaType)
	if err != nil {
		t.Fatalf("failed to get signing time from signature: %v", err)
	}
	expetecSigningTime := "2023-03-14T04:45:22Z"
	if signingTime.Format(time.RFC3339) != expetecSigningTime {
		t.Fatalf("expected signing time: %q, got: %q", expetecSigningTime, signingTime.Format(time.RFC3339))
	}
}

func isErrEqual(wanted, got error) bool {
	if wanted == nil && got == nil {
		return true
	}
	if wanted != nil && got != nil {
		return wanted.Error() == got.Error()
	}
	return false
}

// validateEnvelopeMediaType validetes envelope media type is supported by
// notation-core-go.
func validateEnvelopeMediaType(mediaType string) error {
	for _, types := range signature.RegisteredEnvelopeTypes() {
		if mediaType == types {
			return nil
		}
	}
	return errors.New("invalid envelope media type")
}
