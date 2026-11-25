// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package notation_test

import (
	"context"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const exampleBlob = "example blob"

type signedEnvelopeHeader struct {
	Header struct {
		X5C []string `json:"x5c"`
	} `json:"header"`
}

type fixtureBlobTrustStore struct {
	certificate *x509.Certificate
}

func (s fixtureBlobTrustStore) GetCertificates(_ context.Context, storeType truststore.Type, namedStore string) ([]*x509.Certificate, error) {
	if storeType != truststore.TypeCA || namedStore != "valid-trust-store" {
		return nil, fmt.Errorf("unexpected fixture trust store %s:%s", storeType, namedStore)
	}
	return []*x509.Certificate{s.certificate}, nil
}

func newFixtureBlobVerifier(t *testing.T) notation.BlobVerifier {
	t.Helper()

	signatureBytes := []byte(getSignatureEnvelope())
	var parsed signedEnvelopeHeader
	if err := json.Unmarshal(signatureBytes, &parsed); err != nil {
		t.Fatalf("failed to parse fixture envelope header: %v", err)
	}
	if len(parsed.Header.X5C) == 0 {
		t.Fatal("fixture envelope has no x5c certificate")
	}
	certificateDER, err := base64.StdEncoding.DecodeString(parsed.Header.X5C[0])
	if err != nil {
		t.Fatalf("failed to decode fixture x5c certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatalf("failed to parse fixture certificate: %v", err)
	}

	blobPolicy := trustpolicy.BlobDocument{
		Version: "1.0",
		TrustPolicies: []trustpolicy.BlobTrustPolicy{{
			Name: "test-statement-name",
			SignatureVerification: trustpolicy.SignatureVerification{
				VerificationLevel: trustpolicy.LevelStrict.Name,
				Override: map[trustpolicy.ValidationType]trustpolicy.ValidationAction{
					trustpolicy.TypeRevocation: trustpolicy.ActionSkip,
				},
			},
			TrustStores:       []string{"ca:valid-trust-store"},
			TrustedIdentities: []string{"*"},
		}},
	}
	blobVerifier, err := verifier.NewVerifierWithOptions(fixtureBlobTrustStore{certificate: certificate}, verifier.VerifierOptions{
		BlobTrustPolicy: &blobPolicy,
	})
	if err != nil {
		t.Fatalf("failed to construct fixture verifier: %v", err)
	}
	return blobVerifier
}

func fixtureBlobVerifyOptions(contentMediaType string) notation.VerifyBlobOptions {
	return notation.VerifyBlobOptions{
		BlobVerifierVerifyOptions: notation.BlobVerifierVerifyOptions{
			SignatureMediaType: jws.MediaTypeEnvelope,
			TrustPolicyName:    "test-statement-name",
		},
		ContentMediaType: contentMediaType,
	}
}

func runFixtureBlobVerification(t *testing.T, blobVerifier notation.BlobVerifier, contentMediaType string) (ocispec.Descriptor, *notation.VerificationOutcome, error) {
	t.Helper()
	return notation.VerifyBlob(
		context.Background(),
		blobVerifier,
		strings.NewReader(exampleBlob),
		[]byte(getSignatureEnvelope()),
		fixtureBlobVerifyOptions(contentMediaType),
	)
}

func TestVerifyBlobReturnsSignedTargetArtifact(t *testing.T) {
	blobVerifier := newFixtureBlobVerifier(t)
	descriptor, outcome, err := runFixtureBlobVerification(t, blobVerifier, "video/mp4")
	if err != nil {
		t.Fatalf("VerifyBlob() returned an unexpected error: %v", err)
	}
	if outcome == nil {
		t.Fatal("VerifyBlob() returned a nil outcome after successful verification")
	}

	contentDigest := sha512.Sum384([]byte(exampleBlob))
	wantDigest := fmt.Sprintf("sha384:%x", contentDigest)
	if descriptor.Digest.String() != wantDigest {
		t.Errorf("VerifyBlob() descriptor digest = %q, want %q", descriptor.Digest, wantDigest)
	}
	if descriptor.Size != int64(len(exampleBlob)) {
		t.Errorf("VerifyBlob() descriptor size = %d, want %d", descriptor.Size, len(exampleBlob))
	}
	if descriptor.MediaType != "video/mp4" {
		t.Errorf("VerifyBlob() descriptor media type = %q, want %q", descriptor.MediaType, "video/mp4")
	}
}

func TestVerifyBlobSkipHasNoEnvelopeContent(t *testing.T) {
	policy := trustpolicy.BlobDocument{Version: "1.0", TrustPolicies: []trustpolicy.BlobTrustPolicy{{
		Name:                  "skip-policy",
		SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: trustpolicy.LevelSkip.Name},
	}}}
	blobVerifier, err := verifier.NewVerifierWithOptions(fixtureBlobTrustStore{}, verifier.VerifierOptions{BlobTrustPolicy: &policy})
	if err != nil {
		t.Fatalf("construct skip verifier: %v", err)
	}
	opts := fixtureBlobVerifyOptions("video/mp4")
	opts.TrustPolicyName = "skip-policy"
	desc, outcome, err := notation.VerifyBlob(context.Background(), blobVerifier, strings.NewReader(exampleBlob), []byte(getSignatureEnvelope()), opts)
	if err != nil {
		t.Fatalf("VerifyBlob skip returned error: %v", err)
	}
	if outcome == nil || outcome.VerificationLevel.Name != trustpolicy.LevelSkip.Name {
		t.Fatalf("unexpected skip outcome: %+v", outcome)
	}
	if outcome.EnvelopeContent != nil {
		t.Fatal("expected skip outcome without envelope content")
	}
	if !reflect.DeepEqual(desc, ocispec.Descriptor{}) {
		t.Fatalf("skip descriptor = %+v, want zero value", desc)
	}
}

type invalidOutcomeBlobVerifier struct {
	outcome *notation.VerificationOutcome
}

func (v invalidOutcomeBlobVerifier) VerifyBlob(_ context.Context, _ notation.BlobDescriptorGenerator, _ []byte, _ notation.BlobVerifierVerifyOptions) (*notation.VerificationOutcome, error) {
	return v.outcome, nil
}

func TestVerifyBlobRejectsInvalidVerifierOutcome(t *testing.T) {
	testCases := []struct {
		name    string
		outcome *notation.VerificationOutcome
		wantErr string
	}{
		{
			name:    "nil outcome",
			wantErr: "blob verifier returned a nil verification outcome",
		},
		{
			name:    "missing envelope content and verification level",
			outcome: &notation.VerificationOutcome{},
			wantErr: "blob verifier returned no envelope content",
		},
		{
			name: "missing envelope content without skip",
			outcome: &notation.VerificationOutcome{
				VerificationLevel: trustpolicy.LevelStrict,
			},
			wantErr: "blob verifier returned no envelope content",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			descriptor, outcome, err := runFixtureBlobVerification(t, invalidOutcomeBlobVerifier{outcome: tc.outcome}, "video/mp4")
			if err == nil || err.Error() != tc.wantErr {
				t.Fatalf("VerifyBlob() error = %v, want %q", err, tc.wantErr)
			}
			if outcome != nil {
				t.Errorf("VerifyBlob() outcome = %+v, want nil", outcome)
			}
			if !reflect.DeepEqual(descriptor, ocispec.Descriptor{}) {
				t.Errorf("VerifyBlob() descriptor = %+v, want zero value", descriptor)
			}
		})
	}
}

func TestVerifyBlobContentMediaType(t *testing.T) {
	blobVerifier := newFixtureBlobVerifier(t)

	t.Run("matching signed media type is accepted", func(t *testing.T) {
		_, outcome, err := runFixtureBlobVerification(t, blobVerifier, "video/mp4")
		if err != nil {
			t.Fatalf("VerifyBlob() returned an unexpected error: %v", err)
		}
		if outcome == nil {
			t.Fatal("VerifyBlob() returned a nil outcome after successful verification")
		}
	})

	t.Run("different valid media type is rejected", func(t *testing.T) {
		_, outcome, err := runFixtureBlobVerification(t, blobVerifier, "application/octet-stream")
		if err == nil {
			t.Fatal("VerifyBlob() accepted a media type that differs from the signed artifact")
		}
		if outcome != nil {
			t.Fatalf("VerifyBlob() returned an outcome after rejection: %+v", outcome)
		}
		const wantError = "integrity check failed. signature does not match the given blob"
		if err.Error() != wantError {
			t.Fatalf("VerifyBlob() error = %q, want %q", err, wantError)
		}
	})
}
