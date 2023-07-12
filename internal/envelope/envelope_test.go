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

package envelope

import (
	"errors"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/signature/cose"
	"github.com/notaryproject/notation-core-go/signature/jws"
	gcose "github.com/veraison/go-cose"
)

var (
	validCoseSignatureEnvelope []byte
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
	testTime, err := time.Parse(time.RFC3339, "2023-03-14T04:45:22Z")
	if err != nil {
		t.Fatal("failed to generate time")
	}
	signerInfo := signature.SignerInfo{
		SignedAttributes: signature.SignedAttributes{
			SigningTime: testTime,
		},
	}
	signingTime, err := SigningTime(&signerInfo)
	if err != nil {
		t.Fatalf("failed to get signing time from signature: %v", err)
	}
	expectedSigningTime := "2023-03-14T04:45:22Z"
	if signingTime.Format(time.RFC3339) != expectedSigningTime {
		t.Fatalf("expected signing time: %q, got: %q", expectedSigningTime, signingTime.Format(time.RFC3339))
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
