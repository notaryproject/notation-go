package verification

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/internal/mock"
	"github.com/notaryproject/notation-go/internal/registry"
	"github.com/notaryproject/notation-go/plugin"
	"github.com/notaryproject/notation-go/plugin/manager"

	_ "github.com/notaryproject/notation-core-go/signature/cose"
	_ "github.com/notaryproject/notation-core-go/signature/jws"
)

func verifyResult(outcome *SignatureVerificationOutcome, expectedResult VerificationResult, expectedErr error, t *testing.T) {
	var actualResult *VerificationResult
	for _, r := range outcome.VerificationResults {
		if r.Type == expectedResult.Type {
			if actualResult == nil {
				actualResult = r
			} else {
				t.Fatalf("expected only one VerificatiionResult for %q but found one more. first: %+v second: %+v", r.Type, actualResult, r)
			}
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
		PluginManager:  mock.PluginManager{},
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
		PluginManager:  mock.PluginManager{},
	}

	_, err := verifier.Verify(context.Background(), "non-existent-domain.com/repo@sha256:73c803930ea3ba1e54bc25c2bdc53edd0284c62ed651fe7b00369da519a3c333")
	if !errors.Is(err, ErrorNoApplicableTrustPolicy{msg: "artifact \"non-existent-domain.com/repo@sha256:73c803930ea3ba1e54bc25c2bdc53edd0284c62ed651fe7b00369da519a3c333\" has no applicable trust policy"}) {
		t.Fatalf("no applicable trust policy must throw error")
	}
}

func TestSkippedSignatureVerification(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	policyDocument.TrustPolicies[0].SignatureVerification.Level = "skip"
	verifier := Verifier{
		PolicyDocument: &policyDocument,
		Repository:     mock.NewRepository(),
		PluginManager:  mock.PluginManager{},
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
		PluginManager:  mock.PluginManager{},
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
		PluginManager:  mock.PluginManager{},
	}
	errorMessage := fmt.Sprintf("unable to retrieve digital signature(s) associated with %q from the registry, error : network error", mock.SampleArtifactUri)
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
		PluginManager:  mock.PluginManager{},
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
		PluginManager:  mock.PluginManager{},
	}
	errorMessage := fmt.Sprintf("unable to retrieve digital signature with digest %q associated with %q from the registry, error : network error", mock.SampleDigest, mock.SampleArtifactUri)
	expectedErr := ErrorSignatureRetrievalFailed{msg: errorMessage}

	// mock the repository
	repo.GetError = errors.New("network error")
	_, err := verifier.Verify(context.Background(), mock.SampleArtifactUri)

	if err == nil || !errors.Is(err, expectedErr) {
		t.Fatalf("RegistryGetBlob expected: %v got: %v", expectedErr, err)
	}
}

func TestNotationVerificationCombinations(t *testing.T) {
	assertNotationVerification(t, signature.SigningSchemeX509)
	assertNotationVerification(t, signature.SigningSchemeX509SigningAuthority)
}

func assertNotationVerification(t *testing.T, scheme signature.SigningScheme) {
	var validSigEnv []byte
	var invalidSigEnv []byte
	var expiredSigEnv []byte

	if scheme == signature.SigningSchemeX509 {
		validSigEnv = mock.MockCaValidSigEnv
		invalidSigEnv = mock.MockCaInvalidSigEnv
		expiredSigEnv = mock.MockCaExpiredSigEnv
	} else if scheme == signature.SigningSchemeX509SigningAuthority {
		validSigEnv = mock.MockSaValidSigEnv
		invalidSigEnv = mock.MockSaInvalidSigEnv
		expiredSigEnv = mock.MockSaExpiredSigEnv
	}

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
		repo := mock.NewRepository()
		repo.GetResponse = validSigEnv
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
		repo.GetResponse = invalidSigEnv
		expectedErr := fmt.Errorf("signature is invalid. Error: illegal base64 data at input byte 242")
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
		policyDocument := dummyPolicyDocument() // policy is configured to trust "CN=Notation Test Root,O=Notary,L=Seattle,ST=WA,C=US" which is the subject of the signature's signing certificate
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
	for _, level := range verificationLevels {
		policyDocument := dummyPolicyDocument()
		repo := mock.NewRepository()
		testCases = append(testCases, testCase{
			verificationType:  Expiry,
			verificationLevel: level,
			policyDocument:    policyDocument,
			repository:        repo,
		})
	}

	// Expiry Failure
	for _, level := range verificationLevels {
		policyDocument := dummyPolicyDocument()
		repo := mock.NewRepository()
		repo.GetResponse = expiredSigEnv
		expectedErr := fmt.Errorf("digital signature has expired on \"Fri, 29 Jul 2022 23:59:00 +0000\"")
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
			tt.policyDocument.TrustPolicies[0].SignatureVerification.Level = tt.verificationLevel.Name

			expectedResult := VerificationResult{
				Type:    tt.verificationType,
				Action:  tt.verificationLevel.VerificationMap[tt.verificationType],
				Success: tt.expectedErr == nil,
				Error:   tt.expectedErr,
			}

			dir.UserConfigDir = "testdata"

			pluginManager := mock.PluginManager{}
			pluginManager.GetPluginError = errors.New("plugin should not be invoked when verification plugin is not specified in the signature")
			pluginManager.PluginRunnerLoadError = errors.New("plugin should not be invoked when verification plugin is not specified in the signature")

			verifier := Verifier{
				PolicyDocument: &tt.policyDocument,
				Repository:     &tt.repository,
				PluginManager:  pluginManager,
			}
			outcomes, _ := verifier.Verify(context.Background(), mock.SampleArtifactUri)
			if len(outcomes) != 1 {
				t.Fatalf("there should be only one SignatureVerificationOutcome")
			}
			verifyResult(outcomes[0], expectedResult, tt.expectedErr, t)
		})
	}
}

func TestVerificationPluginInteractions(t *testing.T) {
	assertPluginVerification(signature.SigningSchemeX509, t)
	assertPluginVerification(signature.SigningSchemeX509SigningAuthority, t)
}

func assertPluginVerification(scheme signature.SigningScheme, t *testing.T) {
	var pluginSigEnv []byte
	if scheme == signature.SigningSchemeX509 {
		pluginSigEnv = mock.MockCaPluginSigEnv
	} else if scheme == signature.SigningSchemeX509SigningAuthority {
		pluginSigEnv = mock.MockSaPluginSigEnv
	}

	policyDocument := dummyPolicyDocument()
	repo := mock.NewRepository()
	repo.GetResponse = pluginSigEnv

	dir.UserConfigDir = "testdata"

	// verification plugin is not installed
	pluginManager := mock.PluginManager{}
	pluginManager.GetPluginError = manager.ErrNotFound

	verifier := Verifier{
		PolicyDocument: &policyDocument,
		Repository:     repo,
		PluginManager:  pluginManager,
	}
	outcomes, err := verifier.Verify(context.Background(), mock.SampleArtifactUri)
	if err == nil || outcomes[0].Error == nil || outcomes[0].Error.Error() != "error while locating the verification plugin \"plugin-name\", make sure the plugin is installed successfully before verifying the signature. error: plugin not found" {
		t.Fatalf("verification should fail if the verification plugin is not found")
	}

	// plugin is installed but without verification capabilities
	pluginManager = mock.PluginManager{}
	pluginManager.PluginCapabilities = []plugin.Capability{plugin.CapabilitySignatureGenerator}

	verifier = Verifier{
		PolicyDocument: &policyDocument,
		Repository:     repo,
		PluginManager:  pluginManager,
	}
	outcomes, err = verifier.Verify(context.Background(), mock.SampleArtifactUri)
	if err == nil || outcomes[0].Error == nil || outcomes[0].Error.Error() != "digital signature requires plugin \"plugin-name\" with signature verification capabilities (\"SIGNATURE_VERIFIER.TRUSTED_IDENTITY\" and/or \"SIGNATURE_VERIFIER.REVOCATION_CHECK\") installed" {
		t.Fatalf("verification should fail if the verification plugin is not found")
	}

	// plugin interactions with trusted identity verification success
	pluginManager = mock.PluginManager{}
	pluginManager.PluginCapabilities = []plugin.Capability{plugin.CapabilityTrustedIdentityVerifier}
	pluginManager.PluginRunnerExecuteResponse = &plugin.VerifySignatureResponse{
		VerificationResults: map[plugin.VerificationCapability]*plugin.VerificationResult{
			plugin.VerificationCapabilityTrustedIdentity: {
				Success: true,
			},
		},
		ProcessedAttributes: []interface{}{mock.PluginExtendedCriticalAttribute.Key},
	}

	verifier = Verifier{
		PolicyDocument: &policyDocument,
		Repository:     repo,
		PluginManager:  pluginManager,
	}
	outcomes, err = verifier.Verify(context.Background(), mock.SampleArtifactUri)
	if err != nil || outcomes[0].Error != nil {
		t.Fatalf("verification should succeed when the verification plugin succeeds for trusted identity verification. error : %v", outcomes[0].Error)
	}

	// plugin interactions with trusted identity verification failure
	pluginManager = mock.PluginManager{}
	pluginManager.PluginCapabilities = []plugin.Capability{plugin.CapabilityTrustedIdentityVerifier}
	pluginManager.PluginRunnerExecuteResponse = &plugin.VerifySignatureResponse{
		VerificationResults: map[plugin.VerificationCapability]*plugin.VerificationResult{
			plugin.VerificationCapabilityTrustedIdentity: {
				Success: false,
				Reason:  "i feel like failing today",
			},
		},
		ProcessedAttributes: []interface{}{mock.PluginExtendedCriticalAttribute.Key},
	}

	verifier = Verifier{
		PolicyDocument: &policyDocument,
		Repository:     repo,
		PluginManager:  pluginManager,
	}
	outcomes, err = verifier.Verify(context.Background(), mock.SampleArtifactUri)
	if err == nil || outcomes[0].Error == nil || outcomes[0].Error.Error() != "trusted identify verification by plugin \"plugin-name\" failed with reason \"i feel like failing today\"" {
		t.Fatalf("verification should fail when the verification plugin fails for trusted identity verification. error : %v", outcomes[0].Error)
	}

	// plugin interactions with revocation verification success
	pluginManager = mock.PluginManager{}
	pluginManager.PluginCapabilities = []plugin.Capability{plugin.CapabilityRevocationCheckVerifier}
	pluginManager.PluginRunnerExecuteResponse = &plugin.VerifySignatureResponse{
		VerificationResults: map[plugin.VerificationCapability]*plugin.VerificationResult{
			plugin.VerificationCapabilityRevocationCheck: {
				Success: true,
			},
		},
		ProcessedAttributes: []interface{}{mock.PluginExtendedCriticalAttribute.Key},
	}

	verifier = Verifier{
		PolicyDocument: &policyDocument,
		Repository:     repo,
		PluginManager:  pluginManager,
	}
	outcomes, err = verifier.Verify(context.Background(), mock.SampleArtifactUri)
	if err != nil || outcomes[0].Error != nil {
		t.Fatalf("verification should succeed when the verification plugin succeeds for revocation verification. error : %v", outcomes[0].Error)
	}

	// plugin interactions with trusted revocation failure
	pluginManager = mock.PluginManager{}
	pluginManager.PluginCapabilities = []plugin.Capability{plugin.CapabilityRevocationCheckVerifier}
	pluginManager.PluginRunnerExecuteResponse = &plugin.VerifySignatureResponse{
		VerificationResults: map[plugin.VerificationCapability]*plugin.VerificationResult{
			plugin.VerificationCapabilityRevocationCheck: {
				Success: false,
				Reason:  "i feel like failing today",
			},
		},
		ProcessedAttributes: []interface{}{mock.PluginExtendedCriticalAttribute.Key},
	}

	verifier = Verifier{
		PolicyDocument: &policyDocument,
		Repository:     repo,
		PluginManager:  pluginManager,
	}
	outcomes, err = verifier.Verify(context.Background(), mock.SampleArtifactUri)
	if err == nil || outcomes[0].Error == nil || outcomes[0].Error.Error() != "revocation check by verification plugin \"plugin-name\" failed with reason \"i feel like failing today\"" {
		t.Fatalf("verification should fail when the verification plugin fails for revocation check verification. error : %v", outcomes[0].Error)
	}

	// plugin interactions with both trusted identity & revocation verification
	pluginManager = mock.PluginManager{}
	pluginManager.PluginCapabilities = []plugin.Capability{plugin.CapabilityRevocationCheckVerifier, plugin.CapabilityTrustedIdentityVerifier}
	pluginManager.PluginRunnerExecuteResponse = &plugin.VerifySignatureResponse{
		VerificationResults: map[plugin.VerificationCapability]*plugin.VerificationResult{
			plugin.VerificationCapabilityRevocationCheck: {
				Success: true,
			},
			plugin.VerificationCapabilityTrustedIdentity: {
				Success: true,
			},
		},
		ProcessedAttributes: []interface{}{mock.PluginExtendedCriticalAttribute.Key},
	}

	verifier = Verifier{
		PolicyDocument: &policyDocument,
		Repository:     repo,
		PluginManager:  pluginManager,
	}
	outcomes, err = verifier.Verify(context.Background(), mock.SampleArtifactUri)
	if err != nil || outcomes[0].Error != nil {
		t.Fatalf("verification should succeed when the verification plugin succeeds for both trusted identity and revocation check verifications. error : %v", outcomes[0].Error)
	}

	// plugin interactions with skipped revocation
	policyDocument.TrustPolicies[0].SignatureVerification.Override = map[string]string{"revocation": "skip"}
	pluginManager = mock.PluginManager{}
	pluginManager.PluginCapabilities = []plugin.Capability{plugin.CapabilityRevocationCheckVerifier}
	pluginManager.PluginRunnerExecuteError = errors.New("revocation plugin should not be invoked when the trust policy skips revocation check")

	verifier = Verifier{
		PolicyDocument: &policyDocument,
		Repository:     repo,
		PluginManager:  pluginManager,
	}
	outcomes, err = verifier.Verify(context.Background(), mock.SampleArtifactUri)
	if err != nil || outcomes[0].Error != nil {
		t.Fatalf("revocation plugin should not be invoked when the trust policy skips the revocation check. error : %v", outcomes[0].Error)
	}

	// plugin unexpected response
	pluginManager = mock.PluginManager{}
	pluginManager.PluginCapabilities = []plugin.Capability{plugin.CapabilityTrustedIdentityVerifier}
	pluginManager.PluginRunnerExecuteResponse = "invalid plugin response"

	verifier = Verifier{
		PolicyDocument: &policyDocument,
		Repository:     repo,
		PluginManager:  pluginManager,
	}
	outcomes, err = verifier.Verify(context.Background(), mock.SampleArtifactUri)
	if err == nil || outcomes[0].Error == nil || outcomes[0].Error.Error() != "verification plugin \"plugin-name\" returned unexpected response : \"invalid plugin response\"" {
		t.Fatalf("verification should fail when the verification plugin returns unexpected response. error : %v", outcomes[0].Error)
	}

	// plugin did not process all extended critical attributes
	pluginManager = mock.PluginManager{}
	pluginManager.PluginCapabilities = []plugin.Capability{plugin.CapabilityTrustedIdentityVerifier}
	pluginManager.PluginRunnerExecuteResponse = &plugin.VerifySignatureResponse{
		VerificationResults: map[plugin.VerificationCapability]*plugin.VerificationResult{
			plugin.VerificationCapabilityTrustedIdentity: {
				Success: true,
			},
		},
		ProcessedAttributes: []interface{}{}, // exclude the critical attribute
	}

	verifier = Verifier{
		PolicyDocument: &policyDocument,
		Repository:     repo,
		PluginManager:  pluginManager,
	}
	outcomes, err = verifier.Verify(context.Background(), mock.SampleArtifactUri)
	if err == nil || outcomes[0].Error == nil || outcomes[0].Error.Error() != "extended critical attribute \"SomeKey\" was not processed by the verification plugin \"plugin-name\" (all extended critical attributes must be processed by the verification plugin)" {
		t.Fatalf("verification should fail when the verification plugin fails to process an extended critical attribute. error : %v", outcomes[0].Error)
	}

	// plugin returned empty result for a capability
	pluginManager = mock.PluginManager{}
	pluginManager.PluginCapabilities = []plugin.Capability{plugin.CapabilityTrustedIdentityVerifier}
	pluginManager.PluginRunnerExecuteResponse = &plugin.VerifySignatureResponse{
		VerificationResults: map[plugin.VerificationCapability]*plugin.VerificationResult{},
		ProcessedAttributes: []interface{}{mock.PluginExtendedCriticalAttribute.Key},
	}

	verifier = Verifier{
		PolicyDocument: &policyDocument,
		Repository:     repo,
		PluginManager:  pluginManager,
	}
	outcomes, err = verifier.Verify(context.Background(), mock.SampleArtifactUri)
	if err == nil || outcomes[0].Error == nil || outcomes[0].Error.Error() != "verification plugin \"plugin-name\" failed to verify \"SIGNATURE_VERIFIER.TRUSTED_IDENTITY\"" {
		t.Fatalf("verification should fail when the verification plugin does not return response for a capability. error : %v", outcomes[0].Error)
	}
}
