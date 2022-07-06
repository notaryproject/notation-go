package verification

import (
	"context"
	"errors"
	"fmt"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/internal/mock"
	"github.com/notaryproject/notation-go/registry"
	"strconv"
	"testing"
)

func verifyResult(outcome *SignatureVerificationOutcome, expectedResult VerificationResult, expectedErr error, t *testing.T) {

	var actualResult *VerificationResult
	for _, r := range outcome.VerificationResults {
		if r.Type == expectedResult.Type {
			actualResult = r
			break
		}
	}

	if actualResult == nil ||
		expectedResult.Success != actualResult.Success ||
		(expectedResult.Error != nil && expectedResult.Error.Error() != actualResult.Error.Error()) ||
		expectedResult.Action != actualResult.Action {
		t.Fatalf("assertion failed. expected : %+v got : %+v", expectedResult, actualResult)
	}

	if expectedResult.Action == Enforced && expectedErr != nil && outcome.Error.Error() != expectedErr.Error() {
		t.Fatalf("assertion failed. expected : %v got : %v", expectedErr, outcome.Error)
	}
}

func TestInvalidArtifactUriValidations(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	verifier := Verifier{
		PolicyDocument: &policyDocument,
		Repository:     mock.NewRepository(),
		PluginManager:  mock.NewPluginManager(),
	}

	tests := []struct {
		uri     string
		wantErr bool
	}{
		{"", true},
		{"invaliduri", true},
		{"domain.com/repository@sha256:", true},
		{"domain.com/repository@sha256", true},
		{"domain.com/repository@", true},
		{"domain.com/repository", true},
		{"domain.com/repositorysha256:digest", true},
		{"domain.com/repositorysha256digest", true},
		{"repository@sha256:digest", true},
	}
	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			_, err := verifier.Verify(context.Background(), tt.uri)
			if err != nil != tt.wantErr {
				t.Fatalf("TestInvalidArtifactUriValidations expected error for %q", tt.uri)
			}
		})
	}
}

func TestErrorNoApplicableTrustPolicy_Error(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	verifier := Verifier{
		PolicyDocument: &policyDocument,
		Repository:     mock.NewRepository(),
		PluginManager:  mock.NewPluginManager(),
	}

	_, err := verifier.Verify(context.Background(), "non-existent-domain.com/repo@sha256:73c803930ea3ba1e54bc25c2bdc53edd0284c62ed651fe7b00369da519a3c333")
	if !errors.Is(err, ErrorNoApplicableTrustPolicy{msg: "artifact \"non-existent-domain.com/repo@sha256:73c803930ea3ba1e54bc25c2bdc53edd0284c62ed651fe7b00369da519a3c333\" has no applicable trust policy"}) {
		t.Fatalf("no applicable trust policy must throw error")
	}
}

func TestSkippedSignatureVerification(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	policyDocument.TrustPolicies[0].SignatureVerification = "skip"
	verifier := Verifier{
		PolicyDocument: &policyDocument,
		Repository:     mock.NewRepository(),
		PluginManager:  mock.NewPluginManager(),
	}

	outcomes, err := verifier.Verify(context.Background(), mock.SampleArtifactUri)

	if err != nil || outcomes[0].VerificationLevel != Skip {
		t.Fatalf("\"skip\" verification level must pass overall signature verification")
	}
}

func TestRegistryResolveError(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	repo := mock.NewRepository()
	verifier := Verifier{
		PolicyDocument: &policyDocument,
		Repository:     &repo,
		PluginManager:  mock.NewPluginManager(),
	}
	errorMessage := "network error"
	expectedErr := ErrorSignatureRetrievalFailed{msg: errorMessage}

	// mock the repository
	repo.ResolveError = errors.New(errorMessage)
	_, err := verifier.Verify(context.Background(), mock.SampleArtifactUri)

	if err == nil || !errors.Is(err, expectedErr) {
		t.Fatalf("RegistryResolve expected: %v got: %v", expectedErr, err)
	}
}

func TestRegistryListSignatureManifestsError(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	repo := mock.NewRepository()
	verifier := Verifier{
		PolicyDocument: &policyDocument,
		Repository:     &repo,
		PluginManager:  mock.NewPluginManager(),
	}
	errorMessage := fmt.Sprintf("unable to retrieve digital signature/s associated with %q from the registry, error : network error", mock.SampleArtifactUri)
	expectedErr := ErrorSignatureRetrievalFailed{msg: errorMessage}

	// mock the repository
	repo.ListSignatureManifestsError = errors.New("network error")
	_, err := verifier.Verify(context.Background(), mock.SampleArtifactUri)

	if err == nil || !errors.Is(err, expectedErr) {
		t.Fatalf("RegistryListSignatureManifests expected: %v got: %v", expectedErr, err)
	}
}

func TestRegistryNoSignatureManifests(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	repo := mock.NewRepository()
	verifier := Verifier{
		PolicyDocument: &policyDocument,
		Repository:     &repo,
		PluginManager:  mock.NewPluginManager(),
	}
	errorMessage := fmt.Sprintf("no signatures are associated with %q, make sure the image was signed successfully", mock.SampleArtifactUri)
	expectedErr := ErrorSignatureRetrievalFailed{msg: errorMessage}

	// mock the repository
	repo.ListSignatureManifestsResponse = []registry.SignatureManifest{}
	_, err := verifier.Verify(context.Background(), mock.SampleArtifactUri)

	if err == nil || !errors.Is(err, expectedErr) {
		t.Fatalf("RegistryNoSignatureManifests expected: %v got: %v", expectedErr, err)
	}
}

func TestRegistryGetBlobError(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	repo := mock.NewRepository()
	verifier := Verifier{
		PolicyDocument: &policyDocument,
		Repository:     &repo,
		PluginManager:  mock.NewPluginManager(),
	}
	errorMessage := fmt.Sprintf("unable to retrieve digital signature/s associated with %q from the registry, error : network error", mock.SampleArtifactUri)
	expectedErr := ErrorSignatureRetrievalFailed{msg: errorMessage}

	// mock the repository
	repo.GetError = errors.New("network error")
	_, err := verifier.Verify(context.Background(), mock.SampleArtifactUri)

	if err == nil || !errors.Is(err, expectedErr) {
		t.Fatalf("RegistryGetBlob expected: %v got: %v", expectedErr, err)
	}
}

func TestVerificationCombinations(t *testing.T) {
	type testCase struct {
		verificationType  VerificationType
		verificationLevel *VerificationLevel
		policyDocument    PolicyDocument
		repository        mock.Repository
		expectedErr       error
	}

	var testCases []testCase
	verificationLevels := []*VerificationLevel{Strict, Permissive, Audit}

	// Unsupported Signature Envelope
	for _, level := range verificationLevels {
		policyDocument := dummyPolicyDocument()
		repo := mock.NewRepository()
		repo.ListSignatureManifestsResponse = []registry.SignatureManifest{
			{
				Blob: notation.Descriptor{
					MediaType:   "application/unsupported+json",
					Digest:      mock.SampleDigest,
					Size:        100,
					Annotations: mock.Annotations,
				},
			},
		}
		expectedErr := fmt.Errorf("unable to parse the digital signature, error : signature envelope format with media type \"application/unsupported+json\" is not supported")
		testCases = append(testCases, testCase{
			verificationType:  Integrity,
			verificationLevel: level,
			policyDocument:    policyDocument,
			repository:        repo,
			expectedErr:       expectedErr,
		})
	}

	// Integrity Success
	for _, level := range verificationLevels {
		policyDocument := dummyPolicyDocument()
		repo := mock.NewRepository() // repository returns a valid signature by default
		testCases = append(testCases, testCase{
			verificationType:  Integrity,
			verificationLevel: level,
			policyDocument:    policyDocument,
			repository:        repo,
		})
	}

	// Integrity Failure
	for _, level := range verificationLevels {
		policyDocument := dummyPolicyDocument()
		repo := mock.NewRepository()
		repo.GetResponse = []byte(mock.CorruptedSigEnv)
		expectedErr := fmt.Errorf("signature is invalid. Error: illegal base64 data at input byte 299")
		testCases = append(testCases, testCase{
			verificationType:  Integrity,
			verificationLevel: level,
			policyDocument:    policyDocument,
			repository:        repo,
			expectedErr:       expectedErr,
		})
	}

	// Authenticity Success
	for _, level := range verificationLevels {
		policyDocument := dummyPolicyDocument() // trust store is configured with the root certificate of the signature by default
		repo := mock.NewRepository()
		testCases = append(testCases, testCase{
			verificationType:  Authenticity,
			verificationLevel: level,
			policyDocument:    policyDocument,
			repository:        repo,
		})
	}

	// Authenticity Failure
	for _, level := range verificationLevels {
		policyDocument := dummyPolicyDocument()
		policyDocument.TrustPolicies[0].TrustStores = []string{"ca:valid-trust-store-2"} // trust store is not configured with the root certificate of the signature
		repo := mock.NewRepository()
		expectedErr := fmt.Errorf("signature is not produced by a trusted signer")
		testCases = append(testCases, testCase{
			verificationType:  Authenticity,
			verificationLevel: level,
			policyDocument:    policyDocument,
			repository:        repo,
			expectedErr:       expectedErr,
		})
	}

	// TrustedIdentity Success
	for _, level := range verificationLevels {
		policyDocument := dummyPolicyDocument() // policy is configured to trust "CN=Notation Test Leaf Cert,O=Notary,L=Seattle,ST=WA,C=US" which is the subject of the signature's signing certificate
		repo := mock.NewRepository()
		testCases = append(testCases, testCase{
			verificationType:  Authenticity,
			verificationLevel: level,
			policyDocument:    policyDocument,
			repository:        repo,
		})
	}

	// TrustedIdentity Failure
	for _, level := range verificationLevels {
		policyDocument := dummyPolicyDocument()
		policyDocument.TrustPolicies[0].TrustedIdentities = []string{"x509.subject:CN=LOL,O=DummyOrg,L=Hyderabad,ST=TG,C=IN"} // configure policy to not trust "CN=Notation Test Leaf Cert,O=Notary,L=Seattle,ST=WA,C=US" which is the subject of the signature's signing certificate
		repo := mock.NewRepository()
		expectedErr := fmt.Errorf("signing certificate from the digital signature does not match the X.509 trusted identities [map[\"C\":\"IN\" \"CN\":\"LOL\" \"L\":\"Hyderabad\" \"O\":\"DummyOrg\" \"ST\":\"TG\"]] defined in the trust policy \"test-statement-name\"")
		testCases = append(testCases, testCase{
			verificationType:  Authenticity,
			verificationLevel: level,
			policyDocument:    policyDocument,
			repository:        repo,
			expectedErr:       expectedErr,
		})
	}

	// Expiry Success
	// TODO: generate a signature envelope with 100 years expiry first
	//for _, level := range verificationLevels {
	//	policyDocument := dummyPolicyDocument()
	//	repo := mock.NewRepository()
	//	testCases = append(testCases, testCase{
	//		verificationType:  Expiry,
	//		verificationLevel: level,
	//		policyDocument:    policyDocument,
	//		repository:        repo,
	//	})
	//}

	// Expiry Failure
	for _, level := range verificationLevels {
		policyDocument := dummyPolicyDocument()
		repo := mock.NewRepository() // repository returns an expired signature by default
		expectedErr := fmt.Errorf("digital signature has expired on \"2022-06-25 10:56:22 -0700 PDT\"")
		testCases = append(testCases, testCase{
			verificationType:  Expiry,
			verificationLevel: level,
			policyDocument:    policyDocument,
			repository:        repo,
			expectedErr:       expectedErr,
		})
	}

	for i, tt := range testCases {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			tt.policyDocument.TrustPolicies[0].SignatureVerification = tt.verificationLevel.Name

			expectedResult := VerificationResult{
				Type:   tt.verificationType,
				Action: tt.verificationLevel.VerificationMap[tt.verificationType],
			}
			if tt.expectedErr != nil {
				expectedResult.Success = false
				expectedResult.Error = tt.expectedErr
			} else {
				expectedResult.Success = true
			}

			verifier := Verifier{
				PolicyDocument: &tt.policyDocument,
				Repository:     &tt.repository,
				PluginManager:  mock.NewPluginManager(),
			}
			outcomes, _ := verifier.Verify(context.Background(), mock.SampleArtifactUri)
			if len(outcomes) != 1 {
				t.Fatalf("there should be only one SignatureVerificationOutcome")
			}
			verifyResult(outcomes[0], expectedResult, tt.expectedErr, t)
		})
	}
}
