package notation

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go/internal/mock"
	"github.com/notaryproject/notation-go/plugin"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

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
			opts := SignOptions{
				ExpiryDuration:    tc.dur,
				ArtifactReference: mock.SampleArtifactUri,
			}
			_, err := Sign(context.Background(), &dummySigner{}, repo, opts)
			if err != nil {
				b.Fatalf("Sign failed with error: %v", err)
			}
		})
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
			_, err := Sign(context.Background(), &dummySigner{}, repo, SignOptions{ExpiryDuration: tc.dur})
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
	repo.ResolveError = errors.New(errorMessage)
	opts := RemoteVerifyOptions{ArtifactReference: mock.SampleArtifactUri, MaxSignatureAttempts: 50}
	_, _, err := Verify(context.Background(), &verifier, repo, opts)

	if err == nil || !errors.Is(err, expectedErr) {
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
	opts := RemoteVerifyOptions{ArtifactReference: "localhost/test", MaxSignatureAttempts: 50}
	_, _, err := Verify(context.Background(), &verifier, repo, opts)
	if err == nil || !errors.Is(err, expectedErr) {
		t.Fatalf("VerifyTagReference expected: %v got: %v", expectedErr, err)
	}
}

func TestVerifyTagReferenceFailed(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	repo := mock.NewRepository()
	verifier := dummyVerifier{&policyDocument, mock.PluginManager{}, false, *trustpolicy.LevelStrict}

	errorMessage := "invalid reference: invalid repository"
	expectedErr := ErrorSignatureRetrievalFailed{Msg: errorMessage}

	// mock the repository
	opts := RemoteVerifyOptions{ArtifactReference: "localhost/UPPERCASE/test", MaxSignatureAttempts: 50}
	_, _, err := Verify(context.Background(), &verifier, repo, opts)
	if err == nil || !errors.Is(err, expectedErr) {
		t.Fatalf("VerifyTagReference expected: %v got: %v", expectedErr, err)
	}
}

func TestSkippedSignatureVerification(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	repo := mock.NewRepository()
	verifier := dummyVerifier{&policyDocument, mock.PluginManager{}, false, *trustpolicy.LevelSkip}

	opts := RemoteVerifyOptions{ArtifactReference: mock.SampleArtifactUri, MaxSignatureAttempts: 50}
	_, outcomes, err := Verify(context.Background(), &verifier, repo, opts)

	if err != nil || outcomes[0].VerificationLevel.Name != trustpolicy.LevelSkip.Name {
		t.Fatalf("\"skip\" verification level must pass overall signature verification")
	}
}

func TestRegistryNoSignatureManifests(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	repo := mock.NewRepository()
	verifier := dummyVerifier{&policyDocument, mock.PluginManager{}, false, *trustpolicy.LevelStrict}
	errorMessage := fmt.Sprintf("no signature is associated with %q, make sure the image was signed successfully", mock.SampleArtifactUri)
	expectedErr := ErrorSignatureRetrievalFailed{Msg: errorMessage}

	// mock the repository
	repo.ListSignaturesResponse = []ocispec.Descriptor{}
	opts := RemoteVerifyOptions{ArtifactReference: mock.SampleArtifactUri, MaxSignatureAttempts: 50}
	_, _, err := Verify(context.Background(), &verifier, repo, opts)

	if err == nil || !errors.Is(err, expectedErr) {
		t.Fatalf("RegistryNoSignatureManifests expected: %v got: %v", expectedErr, err)
	}
}

func TestRegistryFetchSignatureBlobError(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	repo := mock.NewRepository()
	verifier := dummyVerifier{&policyDocument, mock.PluginManager{}, false, *trustpolicy.LevelStrict}
	errorMessage := fmt.Sprintf("unable to retrieve digital signature with digest %q associated with %q from the registry, error : network error", mock.SampleDigest, mock.SampleArtifactUri)
	expectedErr := ErrorSignatureRetrievalFailed{Msg: errorMessage}

	// mock the repository
	repo.FetchSignatureBlobError = errors.New("network error")
	opts := RemoteVerifyOptions{ArtifactReference: mock.SampleArtifactUri, MaxSignatureAttempts: 50}
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
	opts := RemoteVerifyOptions{ArtifactReference: mock.SampleArtifactUri, MaxSignatureAttempts: 50}
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
	opts := RemoteVerifyOptions{ArtifactReference: mock.SampleArtifactUri}
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
	opts := RemoteVerifyOptions{ArtifactReference: mock.SampleArtifactUri, MaxSignatureAttempts: 50}
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

type dummySigner struct{}

func (s *dummySigner) Sign(ctx context.Context, desc ocispec.Descriptor, opts SignOptions) ([]byte, *signature.SignerInfo, error) {
	return []byte("ABC"), &signature.SignerInfo{}, nil
}

type dummyVerifier struct {
	TrustPolicyDoc    *trustpolicy.Document
	PluginManager     plugin.Manager
	FailVerify        bool
	VerificationLevel trustpolicy.VerificationLevel
}

func (v *dummyVerifier) Verify(ctx context.Context, desc ocispec.Descriptor, signature []byte, opts VerifyOptions) (*VerificationOutcome, error) {
	outcome := &VerificationOutcome{
		VerificationResults: []*ValidationResult{},
		VerificationLevel:   &v.VerificationLevel,
	}
	if v.FailVerify {
		return outcome, errors.New("failed verify")
	}
	return outcome, nil
}

func (v *dummyVerifier) TrustPolicyDocument() (*trustpolicy.Document, error) {
	return v.TrustPolicyDoc, nil
}
