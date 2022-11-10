package notation

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/notaryproject/notation-go/internal/mock"
	"github.com/notaryproject/notation-go/internal/plugin"
	"github.com/notaryproject/notation-go/internal/plugin/manager"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestRegistryResolveError(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	repo := mock.NewRepository()
	verifier := dummyVerifier{&policyDocument, mock.PluginManager{}, false, *trustpolicy.LevelStrict}

	errorMessage := "network error"
	expectedErr := ErrorSignatureRetrievalFailed{Msg: errorMessage}

	// mock the repository
	repo.ResolveError = errors.New(errorMessage)
	opts := VerifyOptions{ArtifactReference: mock.SampleArtifactUri}
	_, _, err := Verify(context.Background(), &verifier, repo, opts)

	if err == nil || !errors.Is(err, expectedErr) {
		t.Fatalf("RegistryResolve expected: %v got: %v", expectedErr, err)
	}
}

func TestSkippedSignatureVerification(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	repo := mock.NewRepository()
	verifier := dummyVerifier{&policyDocument, mock.PluginManager{}, false, *trustpolicy.LevelSkip}

	opts := VerifyOptions{ArtifactReference: mock.SampleArtifactUri}
	_, outcomes, err := Verify(context.Background(), &verifier, repo, opts)

	if err != nil || outcomes[0].VerificationLevel.Name != trustpolicy.LevelSkip.Name {
		t.Fatalf("\"skip\" verification level must pass overall signature verification")
	}
}

func TestRegistryNoSignatureManifests(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	repo := mock.NewRepository()
	verifier := dummyVerifier{&policyDocument, mock.PluginManager{}, false, *trustpolicy.LevelStrict}
	errorMessage := fmt.Sprintf("no signatures are associated with %q, make sure the image was signed successfully", mock.SampleArtifactUri)
	expectedErr := ErrorSignatureRetrievalFailed{Msg: errorMessage}

	// mock the repository
	repo.ListSignaturesResponse = []ocispec.Descriptor{}
	opts := VerifyOptions{ArtifactReference: mock.SampleArtifactUri}
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
	opts := VerifyOptions{ArtifactReference: mock.SampleArtifactUri}
	_, _, err := Verify(context.Background(), &verifier, repo, opts)

	if err == nil || !errors.Is(err, expectedErr) {
		t.Fatalf("RegistryGetBlob expected: %v got: %v", expectedErr, err)
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

type dummyVerifier struct {
	TrustPolicyDoc    *trustpolicy.Document
	PluginManager     pluginManager
	FailVerify        bool
	VerificationLevel trustpolicy.VerificationLevel
}

func (v *dummyVerifier) Verify(ctx context.Context, signature []byte, opts VerifyOptions) (ocispec.Descriptor, *VerificationOutcome, error) {
	if v.FailVerify {
		return ocispec.Descriptor{}, nil, errors.New("failed verify")
	}
	outcome := &VerificationOutcome{
		VerificationResults: []*ValidationResult{},
		VerificationLevel:   &v.VerificationLevel,
	}
	return ocispec.Descriptor{}, outcome, nil
}

func (v *dummyVerifier) TrustPolicyDocument() (*trustpolicy.Document, error) {
	return v.TrustPolicyDoc, nil
}

// pluginManager is for mocking in unit tests
type pluginManager interface {
	Get(ctx context.Context, name string) (*manager.Plugin, error)
	Runner(name string) (plugin.Runner, error)
}
