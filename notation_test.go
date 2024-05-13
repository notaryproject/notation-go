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

package notation

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/signature/cose"
	"github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-go/internal/mock"
	"github.com/notaryproject/notation-go/plugin"
	"github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote"
)

var expectedMetadata = map[string]string{"foo": "bar", "bar": "foo"}

func TestSignSuccess(t *testing.T) {
	repo := mock.NewRepository()
	testCases := []struct {
		name string
		dur  time.Duration
	}{
		{"expiryInHours", 24 * time.Hour},
		{"oneSecondExpiry", 1 * time.Second},
		{"zeroExpiry", 0},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(b *testing.T) {
			opts := SignOptions{}
			opts.SignatureMediaType = jws.MediaTypeEnvelope
			opts.ExpiryDuration = tc.dur
			opts.ArtifactReference = mock.SampleArtifactUri

			_, err := Sign(context.Background(), &dummySigner{}, repo, opts)
			if err != nil {
				b.Fatalf("Sign failed with error: %v", err)
			}
		})
	}
}

func TestSignBlobSuccess(t *testing.T) {
	reader := strings.NewReader("some content")
	testCases := []struct {
		name     string
		dur      time.Duration
		mtype    string
		agent    string
		pConfig  map[string]string
		metadata map[string]string
	}{
		{"expiryInHours", 24 * time.Hour, "video/mp4", "", nil, nil},
		{"oneSecondExpiry", 1 * time.Second, "video/mp4", "", nil, nil},
		{"zeroExpiry", 0, "video/mp4", "", nil, nil},
		{"validContentType", 1 * time.Second, "video/mp4", "", nil, nil},
		{"emptyContentType", 1 * time.Second, "video/mp4", "someDummyAgent", map[string]string{"hi": "hello"}, map[string]string{"bye": "tata"}},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(b *testing.T) {
			opts := SignBlobOptions{
				SignerSignOptions: SignerSignOptions{
					SignatureMediaType: jws.MediaTypeEnvelope,
					ExpiryDuration:     tc.dur,
					PluginConfig:       tc.pConfig,
					SigningAgent:       tc.agent,
				},
				UserMetadata:     expectedMetadata,
				ContentMediaType: tc.mtype,
			}

			_, _, err := SignBlob(context.Background(), &dummySigner{}, reader, opts)
			if err != nil {
				b.Fatalf("Sign failed with error: %v", err)
			}
		})
	}
}

func TestSignBlobError(t *testing.T) {
	reader := strings.NewReader("some content")
	testCases := []struct {
		name     string
		signer   BlobSigner
		dur      time.Duration
		rdr      io.Reader
		sigMType string
		ctMType  string
		errMsg   string
	}{
		{"negativeExpiry", &dummySigner{}, -1 * time.Second, nil, "video/mp4", jws.MediaTypeEnvelope, "expiry duration cannot be a negative value"},
		{"milliSecExpiry", &dummySigner{}, 1 * time.Millisecond, nil, "video/mp4", jws.MediaTypeEnvelope, "expiry duration supports minimum granularity of seconds"},
		{"invalidContentMediaType", &dummySigner{}, 1 * time.Second, reader, "video/mp4/zoping", jws.MediaTypeEnvelope, "invalid content media-type 'video/mp4/zoping': mime: unexpected content after media subtype"},
		{"emptyContentMediaType", &dummySigner{}, 1 * time.Second, reader, "", jws.MediaTypeEnvelope, "content media-type cannot be empty"},
		{"invalidSignatureMediaType", &dummySigner{}, 1 * time.Second, reader, "", "", "content media-type cannot be empty"},
		{"nilReader", &dummySigner{}, 1 * time.Second, nil, "video/mp4", jws.MediaTypeEnvelope, "blobReader cannot be nil"},
		{"nilSigner", nil, 1 * time.Second, reader, "video/mp4", jws.MediaTypeEnvelope, "signer cannot be nil"},
		{"signerError", &dummySigner{fail: true}, 1 * time.Second, reader, "video/mp4", jws.MediaTypeEnvelope, "expected SignBlob failure"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := SignBlobOptions{
				SignerSignOptions: SignerSignOptions{
					SignatureMediaType: jws.MediaTypeEnvelope,
					ExpiryDuration:     tc.dur,
					PluginConfig:       nil,
				},
				ContentMediaType: tc.sigMType,
			}

			_, _, err := SignBlob(context.Background(), tc.signer, tc.rdr, opts)
			if err == nil {
				t.Fatalf("expected error but didnt found")
			}
			if err.Error() != tc.errMsg {
				t.Fatalf("expected err message to be '%s' but found '%s'", tc.errMsg, err.Error())
			}
		})
	}
}

func TestSignSuccessWithUserMetadata(t *testing.T) {
	repo := mock.NewRepository()
	opts := SignOptions{}
	opts.ArtifactReference = mock.SampleArtifactUri
	opts.UserMetadata = expectedMetadata
	opts.SignatureMediaType = jws.MediaTypeEnvelope

	_, err := Sign(context.Background(), &verifyMetadataSigner{}, repo, opts)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
}

func TestSignWithDanglingReferrersIndex(t *testing.T) {
	repo := mock.NewRepository()
	repo.PushSignatureError = &remote.ReferrersError{
		Op:  "DeleteReferrersIndex",
		Err: errors.New("error"),
	}
	opts := SignOptions{}
	opts.ArtifactReference = mock.SampleArtifactUri
	opts.SignatureMediaType = jws.MediaTypeEnvelope

	_, err := Sign(context.Background(), &dummySigner{}, repo, opts)
	if err == nil {
		t.Fatalf("no error occurred, expected error")
	}
}

func TestSignWithNilRepo(t *testing.T) {
	opts := SignOptions{}
	opts.ArtifactReference = mock.SampleArtifactUri
	opts.SignatureMediaType = jws.MediaTypeEnvelope

	_, err := Sign(context.Background(), &dummySigner{}, nil, opts)
	if err == nil {
		t.Fatalf("no error occurred, expected error: repo cannot be nil")
	}
}

func TestSignResolveFailed(t *testing.T) {
	repo := mock.NewRepository()
	repo.ResolveError = errors.New("resolve error")
	opts := SignOptions{}
	opts.ArtifactReference = mock.SampleArtifactUri
	opts.SignatureMediaType = jws.MediaTypeEnvelope

	_, err := Sign(context.Background(), &dummySigner{}, repo, opts)
	if err == nil {
		t.Fatalf("no error occurred, expected resolve error")
	}
}

func TestSignArtifactRefIsTag(t *testing.T) {
	repo := mock.NewRepository()
	opts := SignOptions{}
	opts.ArtifactReference = "registry.acme-rockets.io/software/net-monitor:v1"
	opts.SignatureMediaType = jws.MediaTypeEnvelope

	_, err := Sign(context.Background(), &dummySigner{}, repo, opts)
	if err != nil {
		t.Fatalf("expect no error, got %s", err)
	}
}

func TestSignWithPushSignatureError(t *testing.T) {
	repo := mock.NewRepository()
	repo.PushSignatureError = errors.New("error")
	opts := SignOptions{}
	opts.ArtifactReference = mock.SampleArtifactUri
	opts.SignatureMediaType = jws.MediaTypeEnvelope

	_, err := Sign(context.Background(), &dummySigner{}, repo, opts)
	if err == nil {
		t.Fatalf("no error occurred, expected error: failed to delete dangling referrers index")
	}
}

func TestSignWithInvalidExpiry(t *testing.T) {
	repo := mock.NewRepository()
	testCases := []struct {
		name string
		dur  time.Duration
	}{
		{"negativeExpiry", -24 * time.Hour},
		{"splitSecondExpiry", 1 * time.Millisecond},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(b *testing.T) {
			opts := SignOptions{}
			opts.ExpiryDuration = tc.dur

			_, err := Sign(context.Background(), &dummySigner{}, repo, opts)
			if err == nil {
				b.Fatalf("Expected error but not found")
			}
		})
	}
}

func TestSignWithInvalidUserMetadata(t *testing.T) {
	repo := mock.NewRepository()
	testCases := []struct {
		name     string
		metadata map[string]string
	}{
		{"reservedAnnotationKey", map[string]string{reservedAnnotationPrefixes[0] + ".foo": "bar"}},
		{"keyConflict", map[string]string{"key": "value2"}},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(b *testing.T) {
			opts := SignOptions{
				UserMetadata: tc.metadata,
				SignerSignOptions: SignerSignOptions{
					SignatureMediaType: jws.MediaTypeEnvelope,
				},
			}

			_, err := Sign(context.Background(), &dummySigner{}, repo, opts)
			if err == nil {
				b.Fatalf("Expected error but not found")
			}
		})
	}
}

func TestRegistryResolveError(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	repo := mock.NewRepository()
	verifier := dummyVerifier{&policyDocument, mock.PluginManager{}, false, *trustpolicy.LevelStrict}

	errorMessage := "network error"
	expectedErr := ErrorSignatureRetrievalFailed{Msg: errorMessage}

	// mock the repository
	repo.ResolveError = errors.New("network error")
	opts := VerifyOptions{ArtifactReference: mock.SampleArtifactUri, MaxSignatureAttempts: 50}
	_, _, err := Verify(context.Background(), &verifier, repo, opts)

	if err == nil || err.Error() != errorMessage {
		t.Fatalf("RegistryResolve expected: %v got: %v", expectedErr, err)
	}
}

func TestVerifyEmptyReference(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	repo := mock.NewRepository()
	verifier := dummyVerifier{&policyDocument, mock.PluginManager{}, false, *trustpolicy.LevelStrict}

	errorMessage := "reference is missing digest or tag"
	expectedErr := ErrorSignatureRetrievalFailed{Msg: errorMessage}

	// mock the repository
	opts := VerifyOptions{ArtifactReference: "localhost/test", MaxSignatureAttempts: 50}
	_, _, err := Verify(context.Background(), &verifier, repo, opts)
	if err == nil || err.Error() != errorMessage {
		t.Fatalf("VerifyTagReference expected: %v got: %v", expectedErr, err)
	}
}

func TestVerifyTagReferenceFailed(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	repo := mock.NewRepository()
	verifier := dummyVerifier{&policyDocument, mock.PluginManager{}, false, *trustpolicy.LevelStrict}

	errorMessage := "invalid reference: invalid repository \"UPPERCASE/test\""
	expectedErr := ErrorSignatureRetrievalFailed{Msg: errorMessage}

	// mock the repository
	opts := VerifyOptions{ArtifactReference: "localhost/UPPERCASE/test", MaxSignatureAttempts: 50}
	_, _, err := Verify(context.Background(), &verifier, repo, opts)
	if err == nil || err.Error() != errorMessage {
		t.Fatalf("VerifyTagReference expected: %v got: %v", expectedErr, err)
	}
}

func TestVerifyDigestNotMatchResolve(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	repo := mock.NewRepository()
	repo.MissMatchDigest = true
	verifier := dummyVerifier{&policyDocument, mock.PluginManager{}, false, *trustpolicy.LevelStrict}

	errorMessage := fmt.Sprintf("user input digest %s does not match the resolved digest %s", mock.SampleDigest, mock.ZeroDigest)
	expectedErr := ErrorSignatureRetrievalFailed{Msg: errorMessage}

	// mock the repository
	opts := VerifyOptions{ArtifactReference: mock.SampleArtifactUri, MaxSignatureAttempts: 50}
	_, _, err := Verify(context.Background(), &verifier, repo, opts)
	if err == nil || err.Error() != errorMessage {
		t.Fatalf("VerifyDigestNotMatch expected: %v got: %v", expectedErr, err)
	}
}

func TestSignDigestNotMatchResolve(t *testing.T) {
	repo := mock.NewRepository()
	repo.MissMatchDigest = true
	signOpts := SignOptions{
		SignerSignOptions: SignerSignOptions{
			SignatureMediaType: jws.MediaTypeEnvelope,
		},
		ArtifactReference: mock.SampleArtifactUri,
	}

	errorMessage := fmt.Sprintf("user input digest %s does not match the resolved digest %s", mock.SampleDigest, mock.ZeroDigest)
	expectedErr := fmt.Errorf(errorMessage)

	_, err := Sign(context.Background(), &dummySigner{}, repo, signOpts)
	if err == nil || err.Error() != errorMessage {
		t.Fatalf("SignDigestNotMatch expected: %v got: %v", expectedErr, err)
	}
}

func TestSkippedSignatureVerification(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	repo := mock.NewRepository()
	verifier := dummyVerifier{&policyDocument, mock.PluginManager{}, false, *trustpolicy.LevelSkip}

	opts := VerifyOptions{ArtifactReference: mock.SampleArtifactUri, MaxSignatureAttempts: 50}
	_, outcomes, err := Verify(context.Background(), &verifier, repo, opts)

	if err != nil || outcomes[0].VerificationLevel.Name != trustpolicy.LevelSkip.Name {
		t.Fatalf("\"skip\" verification level must pass overall signature verification")
	}
}

func TestRegistryNoSignatureManifests(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	repo := mock.NewRepository()
	verifier := dummyVerifier{&policyDocument, mock.PluginManager{}, false, *trustpolicy.LevelStrict}
	errorMessage := fmt.Sprintf("no signature is associated with %q, make sure the artifact was signed successfully", mock.SampleArtifactUri)
	expectedErr := ErrorSignatureRetrievalFailed{Msg: errorMessage}

	// mock the repository
	repo.ListSignaturesResponse = []ocispec.Descriptor{}
	opts := VerifyOptions{ArtifactReference: mock.SampleArtifactUri, MaxSignatureAttempts: 50}
	_, _, err := Verify(context.Background(), &verifier, repo, opts)

	if err == nil || !errors.Is(err, expectedErr) {
		t.Fatalf("RegistryNoSignatureManifests expected: %v got: %v", expectedErr, err)
	}
}

func TestRegistryFetchSignatureBlobError(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	repo := mock.NewRepository()
	verifier := dummyVerifier{&policyDocument, mock.PluginManager{}, false, *trustpolicy.LevelStrict}
	errorMessage := fmt.Sprintf("unable to retrieve digital signature with digest %q associated with %q from the Repository, error : network error", mock.SampleDigest, mock.SampleArtifactUri)
	expectedErr := ErrorSignatureRetrievalFailed{Msg: errorMessage}

	// mock the repository
	repo.FetchSignatureBlobError = errors.New("network error")
	opts := VerifyOptions{ArtifactReference: mock.SampleArtifactUri, MaxSignatureAttempts: 50}
	_, _, err := Verify(context.Background(), &verifier, repo, opts)

	if err == nil || !errors.Is(err, expectedErr) {
		t.Fatalf("RegistryFetchSignatureBlob expected: %v got: %v", expectedErr, err)
	}
}

func TestVerifyValid(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	repo := mock.NewRepository()
	verifier := dummyVerifier{&policyDocument, mock.PluginManager{}, false, *trustpolicy.LevelStrict}

	// mock the repository
	opts := VerifyOptions{ArtifactReference: mock.SampleArtifactUri, MaxSignatureAttempts: 50}
	_, _, err := Verify(context.Background(), &verifier, repo, opts)

	if err != nil {
		t.Fatalf("SignaureMediaTypeMismatch expected: %v got: %v", nil, err)
	}
}

func TestMaxSignatureAttemptsMissing(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	repo := mock.NewRepository()
	verifier := dummyVerifier{&policyDocument, mock.PluginManager{}, false, *trustpolicy.LevelStrict}
	expectedErr := ErrorSignatureRetrievalFailed{Msg: fmt.Sprintf("verifyOptions.MaxSignatureAttempts expects a positive number, got %d", 0)}

	// mock the repository
	opts := VerifyOptions{ArtifactReference: mock.SampleArtifactUri}
	_, _, err := Verify(context.Background(), &verifier, repo, opts)

	if err == nil || !errors.Is(err, expectedErr) {
		t.Fatalf("VerificationFailed expected: %v got: %v", expectedErr, err)
	}
}

func TestExceededMaxSignatureAttempts(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	repo := mock.NewRepository()
	repo.ExceededNumOfSignatures = true
	verifier := dummyVerifier{&policyDocument, mock.PluginManager{}, true, *trustpolicy.LevelStrict}
	expectedErr := ErrorVerificationFailed{Msg: fmt.Sprintf("signature evaluation stopped. The configured limit of %d signatures to verify per artifact exceeded", 1)}

	// mock the repository
	opts := VerifyOptions{ArtifactReference: mock.SampleArtifactUri, MaxSignatureAttempts: 1}
	_, _, err := Verify(context.Background(), &verifier, repo, opts)

	if err == nil || !errors.Is(err, expectedErr) {
		t.Fatalf("VerificationFailed expected: %v got: %v", expectedErr, err)
	}
}

func TestVerifyFailed(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	repo := mock.NewRepository()
	verifier := dummyVerifier{&policyDocument, mock.PluginManager{}, true, *trustpolicy.LevelStrict}
	expectedErr := ErrorVerificationFailed{}

	// mock the repository
	opts := VerifyOptions{ArtifactReference: mock.SampleArtifactUri, MaxSignatureAttempts: 50}
	_, _, err := Verify(context.Background(), &verifier, repo, opts)

	if err == nil || !errors.Is(err, expectedErr) {
		t.Fatalf("VerificationFailed expected: %v got: %v", expectedErr, err)
	}
}

func dummyPolicyDocument() (policyDoc trustpolicy.Document) {
	policyDoc = trustpolicy.Document{
		Version:       "1.0",
		TrustPolicies: []trustpolicy.TrustPolicy{dummyPolicyStatement()},
	}
	return
}

func dummyPolicyStatement() (policyStatement trustpolicy.TrustPolicy) {
	policyStatement = trustpolicy.TrustPolicy{
		Name:                  "test-statement-name",
		RegistryScopes:        []string{"registry.acme-rockets.io/software/net-monitor"},
		SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: "strict"},
		TrustStores:           []string{"ca:valid-trust-store", "signingAuthority:valid-trust-store"},
		TrustedIdentities:     []string{"x509.subject:CN=Notation Test Root,O=Notary,L=Seattle,ST=WA,C=US"},
	}
	return
}

type dummySigner struct {
	fail bool
}

func (s *dummySigner) Sign(ctx context.Context, desc ocispec.Descriptor, opts SignerSignOptions) ([]byte, *signature.SignerInfo, error) {
	return []byte("ABC"), &signature.SignerInfo{
		SignedAttributes: signature.SignedAttributes{
			SigningTime: time.Now(),
		},
	}, nil
}

func (s *dummySigner) SignBlob(_ context.Context, descGenFunc BlobDescriptorGenerator, _ SignerSignOptions) ([]byte, *signature.SignerInfo, error) {
	if s.fail {
		return nil, nil, errors.New("expected SignBlob failure")
	}

	_, err := descGenFunc(digest.SHA384)
	if err != nil {
		return nil, nil, err
	}

	return []byte("ABC"), &signature.SignerInfo{
		SignedAttributes: signature.SignedAttributes{
			SigningTime: time.Now(),
		},
	}, nil
}

type verifyMetadataSigner struct{}

func (s *verifyMetadataSigner) Sign(ctx context.Context, desc ocispec.Descriptor, opts SignerSignOptions) ([]byte, *signature.SignerInfo, error) {
	for k, v := range expectedMetadata {
		if desc.Annotations[k] != v {
			return nil, nil, errors.New("expected metadata not present in descriptor")
		}
	}
	return []byte("ABC"), &signature.SignerInfo{
		SignedAttributes: signature.SignedAttributes{
			SigningTime: time.Now(),
		},
	}, nil
}

type dummyVerifier struct {
	TrustPolicyDoc    *trustpolicy.Document
	PluginManager     plugin.Manager
	FailVerify        bool
	VerificationLevel trustpolicy.VerificationLevel
}

func (v *dummyVerifier) Verify(ctx context.Context, desc ocispec.Descriptor, signature []byte, opts VerifierVerifyOptions) (*VerificationOutcome, error) {
	outcome := &VerificationOutcome{
		VerificationResults: []*ValidationResult{},
		VerificationLevel:   &v.VerificationLevel,
	}
	if v.FailVerify {
		return outcome, errors.New("failed verify")
	}
	return outcome, nil
}

var (
	ociLayoutPath     = filepath.FromSlash("./internal/testdata/oci-layout")
	reference         = "sha256:19dbd2e48e921426ee8ace4dc892edfb2ecdc1d1a72d5416c83670c30acecef0"
	artifactReference = "local/oci-layout@sha256:19dbd2e48e921426ee8ace4dc892edfb2ecdc1d1a72d5416c83670c30acecef0"
	signaturePath     = filepath.FromSlash("./internal/testdata/cose_signature.sig")
)

type ociDummySigner struct{}

func (s *ociDummySigner) Sign(ctx context.Context, desc ocispec.Descriptor, opts SignerSignOptions) ([]byte, *signature.SignerInfo, error) {
	sigBlob, err := os.ReadFile(signaturePath)
	if err != nil {
		return nil, nil, err
	}
	sigEnv, err := signature.ParseEnvelope(opts.SignatureMediaType, sigBlob)
	if err != nil {
		return nil, nil, err
	}
	content, err := sigEnv.Content()
	if err != nil {
		return nil, nil, err
	}
	return sigBlob, &content.SignerInfo, nil
}

func TestSignLocalContent(t *testing.T) {
	repo, err := registry.NewOCIRepository(ociLayoutPath, registry.RepositoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	signOpts := SignOptions{
		SignerSignOptions: SignerSignOptions{
			SignatureMediaType: cose.MediaTypeEnvelope,
		},
		ArtifactReference: reference,
	}
	_, err = Sign(context.Background(), &ociDummySigner{}, repo, signOpts)
	if err != nil {
		t.Fatalf("failed to Sign: %v", err)
	}
}

func TestVerifyLocalContent(t *testing.T) {
	repo, err := registry.NewOCIRepository(ociLayoutPath, registry.RepositoryOptions{})
	if err != nil {
		t.Fatalf("failed to create oci.Store as registry.Repository: %v", err)
	}
	verifyOpts := VerifyOptions{
		ArtifactReference:    artifactReference,
		MaxSignatureAttempts: math.MaxInt64,
	}
	policyDocument := dummyPolicyDocument()
	verifier := dummyVerifier{&policyDocument, mock.PluginManager{}, false, *trustpolicy.LevelStrict}
	// verify signatures inside the OCI layout folder
	_, _, err = Verify(context.Background(), &verifier, repo, verifyOpts)
	if err != nil {
		t.Fatalf("failed to verify local content: %v", err)
	}
}
