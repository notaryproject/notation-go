package verifier

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
	"github.com/notaryproject/notation-go/internal/plugin"
	"github.com/notaryproject/notation-go/internal/plugin/manager"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"

	_ "github.com/notaryproject/notation-core-go/signature/cose"
	_ "github.com/notaryproject/notation-core-go/signature/jws"
)

func verifyResult(outcome *notation.VerificationOutcome, expectedResult notation.ValidationResult, expectedErr error, t *testing.T) {
	var actualResult *notation.ValidationResult
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
		(expectedResult.Error != nil && expectedResult.Error.Error() != actualResult.Error.Error()) ||
		expectedResult.Action != actualResult.Action {
		t.Fatalf("assertion failed. expected : %+v got : %+v", expectedResult, actualResult)
	}

	if expectedResult.Action == trustpolicy.ActionEnforce && expectedErr != nil && outcome.Error.Error() != expectedErr.Error() {
		t.Fatalf("assertion failed. expected : %v got : %v", expectedErr, outcome.Error)
	}
}

func TestInvalidArtifactUriValidations(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	verifier := verifier{
		trustPolicyDoc: &policyDocument,
		pluginManager:  mock.PluginManager{},
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
			opts := notation.VerifyOptions{ArtifactReference: tt.uri}
			_, _, err := verifier.Verify(context.Background(), []byte{}, opts)
			if err != nil != tt.wantErr {
				t.Fatalf("TestInvalidArtifactUriValidations expected error for %q", tt.uri)
			}
		})
	}
}

func TestErrorNoApplicableTrustPolicy_Error(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	verifier := verifier{
		trustPolicyDoc: &policyDocument,
		pluginManager:  mock.PluginManager{},
	}
	opts := notation.VerifyOptions{ArtifactReference: "non-existent-domain.com/repo@sha256:73c803930ea3ba1e54bc25c2bdc53edd0284c62ed651fe7b00369da519a3c333"}
	_, _, err := verifier.Verify(context.Background(), []byte{}, opts)
	if !errors.Is(err, notation.ErrorNoApplicableTrustPolicy{Msg: "artifact \"non-existent-domain.com/repo@sha256:73c803930ea3ba1e54bc25c2bdc53edd0284c62ed651fe7b00369da519a3c333\" has no applicable trust policy"}) {
		t.Fatalf("no applicable trust policy must throw error")
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
		signatureBlob     []byte
		verificationType  trustpolicy.ValidationType
		verificationLevel *trustpolicy.VerificationLevel
		policyDocument    trustpolicy.Document
		opts              notation.VerifyOptions
		expectedErr       error
	}

	var testCases []testCase
	verificationLevels := []*trustpolicy.VerificationLevel{trustpolicy.LevelStrict, trustpolicy.LevelPermissive, trustpolicy.LevelAudit}

	// Unsupported Signature Envelope
	for _, level := range verificationLevels {
		policyDocument := dummyPolicyDocument()
		expectedErr := fmt.Errorf("unable to parse the digital signature, error : signature envelope format with media type \"application/unsupported+json\" is not supported")
		testCases = append(testCases, testCase{
			verificationType:  trustpolicy.TypeIntegrity,
			verificationLevel: level,
			policyDocument:    policyDocument,
			opts:              notation.VerifyOptions{ArtifactReference: mock.SampleArtifactUri, SignatureMediaType: "application/unsupported+json"},
			expectedErr:       expectedErr,
		})
	}

	// Integrity Success
	for _, level := range verificationLevels {
		policyDocument := dummyPolicyDocument()
		testCases = append(testCases, testCase{
			signatureBlob:     validSigEnv,
			verificationType:  trustpolicy.TypeIntegrity,
			verificationLevel: level,
			policyDocument:    policyDocument,
			opts:              notation.VerifyOptions{ArtifactReference: mock.SampleArtifactUri, SignatureMediaType: "application/jose+json"},
		})
	}

	// Integrity Failure
	for _, level := range verificationLevels {
		policyDocument := dummyPolicyDocument()
		expectedErr := fmt.Errorf("signature is invalid. Error: illegal base64 data at input byte 242")
		testCases = append(testCases, testCase{
			signatureBlob:     invalidSigEnv,
			verificationType:  trustpolicy.TypeIntegrity,
			verificationLevel: level,
			policyDocument:    policyDocument,
			opts:              notation.VerifyOptions{ArtifactReference: mock.SampleArtifactUri, SignatureMediaType: "application/jose+json"},
			expectedErr:       expectedErr,
		})
	}

	// Authenticity Success
	for _, level := range verificationLevels {
		policyDocument := dummyPolicyDocument() // trust store is configured with the root certificate of the signature by default
		testCases = append(testCases, testCase{
			signatureBlob:     validSigEnv,
			verificationType:  trustpolicy.TypeAuthenticity,
			verificationLevel: level,
			policyDocument:    policyDocument,
			opts:              notation.VerifyOptions{ArtifactReference: mock.SampleArtifactUri, SignatureMediaType: "application/jose+json"},
		})
	}

	// Authenticity Failure
	for _, level := range verificationLevels {
		policyDocument := dummyPolicyDocument()
		policyDocument.TrustPolicies[0].TrustStores = []string{"ca:valid-trust-store-2", "signingAuthority:valid-trust-store-2"} // trust store is not configured with the root certificate of the signature
		expectedErr := fmt.Errorf("signature is not produced by a trusted signer")
		testCases = append(testCases, testCase{
			signatureBlob:     validSigEnv,
			verificationType:  trustpolicy.TypeAuthenticity,
			verificationLevel: level,
			policyDocument:    policyDocument,
			opts:              notation.VerifyOptions{ArtifactReference: mock.SampleArtifactUri, SignatureMediaType: "application/jose+json"},
			expectedErr:       expectedErr,
		})
	}

	// TrustedIdentity Failure
	for _, level := range verificationLevels {
		policyDocument := dummyPolicyDocument()
		policyDocument.TrustPolicies[0].TrustedIdentities = []string{"x509.subject:CN=LOL,O=DummyOrg,L=Hyderabad,ST=TG,C=IN"} // configure policy to not trust "CN=Notation Test Leaf Cert,O=Notary,L=Seattle,ST=WA,C=US" which is the subject of the signature's signing certificate
		expectedErr := fmt.Errorf("signing certificate from the digital signature does not match the X.509 trusted identities [map[\"C\":\"IN\" \"CN\":\"LOL\" \"L\":\"Hyderabad\" \"O\":\"DummyOrg\" \"ST\":\"TG\"]] defined in the trust policy \"test-statement-name\"")
		testCases = append(testCases, testCase{
			signatureBlob:     validSigEnv,
			verificationType:  trustpolicy.TypeAuthenticity,
			verificationLevel: level,
			policyDocument:    policyDocument,
			opts:              notation.VerifyOptions{ArtifactReference: mock.SampleArtifactUri, SignatureMediaType: "application/jose+json"},
			expectedErr:       expectedErr,
		})
	}

	// Expiry Success
	for _, level := range verificationLevels {
		policyDocument := dummyPolicyDocument()
		testCases = append(testCases, testCase{
			signatureBlob:     validSigEnv,
			verificationType:  trustpolicy.TypeExpiry,
			verificationLevel: level,
			policyDocument:    policyDocument,
			opts:              notation.VerifyOptions{ArtifactReference: mock.SampleArtifactUri, SignatureMediaType: "application/jose+json"},
		})
	}

	// Expiry Failure
	for _, level := range verificationLevels {
		policyDocument := dummyPolicyDocument()
		expectedErr := fmt.Errorf("digital signature has expired on \"Fri, 29 Jul 2022 23:59:00 +0000\"")
		testCases = append(testCases, testCase{
			signatureBlob:     expiredSigEnv,
			verificationType:  trustpolicy.TypeExpiry,
			verificationLevel: level,
			policyDocument:    policyDocument,
			opts:              notation.VerifyOptions{ArtifactReference: mock.SampleArtifactUri, SignatureMediaType: "application/jose+json"},
			expectedErr:       expectedErr,
		})
	}

	for i, tt := range testCases {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			tt.policyDocument.TrustPolicies[0].SignatureVerification.VerificationLevel = tt.verificationLevel.Name

			expectedResult := notation.ValidationResult{
				Type:   tt.verificationType,
				Action: tt.verificationLevel.Enforcement[tt.verificationType],
				Error:  tt.expectedErr,
			}

			dir.UserConfigDir = "testdata"

			pluginManager := mock.PluginManager{}
			pluginManager.GetPluginError = errors.New("plugin should not be invoked when verification plugin is not specified in the signature")
			pluginManager.PluginRunnerLoadError = errors.New("plugin should not be invoked when verification plugin is not specified in the signature")

			verifier := verifier{
				trustPolicyDoc: &tt.policyDocument,
				pluginManager:  pluginManager,
			}
			_, outcome, _ := verifier.Verify(context.Background(), tt.signatureBlob, tt.opts)
			verifyResult(outcome, expectedResult, tt.expectedErr, t)
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
	dir.UserConfigDir = "testdata"

	// verification plugin is not installed
	pluginManager := mock.PluginManager{}
	pluginManager.GetPluginError = manager.ErrNotFound

	v := verifier{
		trustPolicyDoc: &policyDocument,
		pluginManager:  pluginManager,
	}
	opts := notation.VerifyOptions{ArtifactReference: mock.SampleArtifactUri, SignatureMediaType: "application/jose+json"}
	_, outcome, err := v.Verify(context.Background(), pluginSigEnv, opts)
	if err == nil || outcome.Error == nil || outcome.Error.Error() != "error while locating the verification plugin \"plugin-name\", make sure the plugin is installed successfully before verifying the signature. error: plugin not found" {
		t.Fatalf("verification should fail if the verification plugin is not found")
	}

	// plugin is installed but without verification capabilities
	pluginManager = mock.PluginManager{}
	pluginManager.PluginCapabilities = []plugin.Capability{plugin.CapabilitySignatureGenerator}

	v = verifier{
		trustPolicyDoc: &policyDocument,
		pluginManager:  pluginManager,
	}
	opts = notation.VerifyOptions{ArtifactReference: mock.SampleArtifactUri, SignatureMediaType: "application/jose+json"}
	_, outcome, err = v.Verify(context.Background(), pluginSigEnv, opts)
	if err == nil || outcome.Error == nil || outcome.Error.Error() != "digital signature requires plugin \"plugin-name\" with signature verification capabilities (\"SIGNATURE_VERIFIER.TRUSTED_IDENTITY\" and/or \"SIGNATURE_VERIFIER.REVOCATION_CHECK\") installed" {
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

	v = verifier{
		trustPolicyDoc: &policyDocument,
		pluginManager:  pluginManager,
	}
	opts = notation.VerifyOptions{ArtifactReference: mock.SampleArtifactUri, SignatureMediaType: "application/jose+json"}
	_, outcome, err = v.Verify(context.Background(), pluginSigEnv, opts)
	if err != nil || outcome.Error != nil {
		t.Fatalf("verification should succeed when the verification plugin succeeds for trusted identity verification. error : %v", outcome.Error)
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

	v = verifier{
		trustPolicyDoc: &policyDocument,
		pluginManager:  pluginManager,
	}
	opts = notation.VerifyOptions{ArtifactReference: mock.SampleArtifactUri, SignatureMediaType: "application/jose+json"}
	_, outcome, err = v.Verify(context.Background(), pluginSigEnv, opts)
	if err == nil || outcome.Error == nil || outcome.Error.Error() != "trusted identify verification by plugin \"plugin-name\" failed with reason \"i feel like failing today\"" {
		t.Fatalf("verification should fail when the verification plugin fails for trusted identity verification. error : %v", outcome.Error)
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

	v = verifier{
		trustPolicyDoc: &policyDocument,
		pluginManager:  pluginManager,
	}
	opts = notation.VerifyOptions{ArtifactReference: mock.SampleArtifactUri, SignatureMediaType: "application/jose+json"}
	_, outcome, err = v.Verify(context.Background(), pluginSigEnv, opts)
	if err != nil || outcome.Error != nil {
		t.Fatalf("verification should succeed when the verification plugin succeeds for revocation verification. error : %v", outcome.Error)
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

	v = verifier{
		trustPolicyDoc: &policyDocument,
		pluginManager:  pluginManager,
	}
	opts = notation.VerifyOptions{ArtifactReference: mock.SampleArtifactUri, SignatureMediaType: "application/jose+json"}
	_, outcome, err = v.Verify(context.Background(), pluginSigEnv, opts)
	if err == nil || outcome.Error == nil || outcome.Error.Error() != "revocation check by verification plugin \"plugin-name\" failed with reason \"i feel like failing today\"" {
		t.Fatalf("verification should fail when the verification plugin fails for revocation check verification. error : %v", outcome.Error)
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

	v = verifier{
		trustPolicyDoc: &policyDocument,
		pluginManager:  pluginManager,
	}
	opts = notation.VerifyOptions{ArtifactReference: mock.SampleArtifactUri, SignatureMediaType: "application/jose+json"}
	_, outcome, err = v.Verify(context.Background(), pluginSigEnv, opts)
	if err != nil || outcome.Error != nil {
		t.Fatalf("verification should succeed when the verification plugin succeeds for both trusted identity and revocation check verifications. error : %v", outcome.Error)
	}

	// plugin interactions with skipped revocation
	policyDocument.TrustPolicies[0].SignatureVerification.Override = map[trustpolicy.ValidationType]trustpolicy.ValidationAction{trustpolicy.TypeRevocation: trustpolicy.ActionSkip}
	pluginManager = mock.PluginManager{}
	pluginManager.PluginCapabilities = []plugin.Capability{plugin.CapabilityRevocationCheckVerifier}
	pluginManager.PluginRunnerExecuteError = errors.New("revocation plugin should not be invoked when the trust policy skips revocation check")

	v = verifier{
		trustPolicyDoc: &policyDocument,
		pluginManager:  pluginManager,
	}
	opts = notation.VerifyOptions{ArtifactReference: mock.SampleArtifactUri, SignatureMediaType: "application/jose+json"}
	trustPolicy, err := (&policyDocument).GetApplicableTrustPolicy(opts.ArtifactReference)
	if err != nil {
		t.Fatalf("cannot get trustPolicy")
	}
	verificationLevel, _ := trustPolicy.SignatureVerification.GetVerificationLevel()
	outcome = &notation.VerificationOutcome{
		VerificationResults: []*notation.ValidationResult{},
		VerificationLevel:   verificationLevel,
	}
	_, outcome, err = v.Verify(context.Background(), pluginSigEnv, opts)
	if err != nil || outcome.Error != nil {
		t.Fatalf("revocation plugin should not be invoked when the trust policy skips the revocation check. error : %v", outcome.Error)
	}

	// plugin unexpected response
	pluginManager = mock.PluginManager{}
	pluginManager.PluginCapabilities = []plugin.Capability{plugin.CapabilityTrustedIdentityVerifier}
	pluginManager.PluginRunnerExecuteResponse = "invalid plugin response"

	v = verifier{
		trustPolicyDoc: &policyDocument,
		pluginManager:  pluginManager,
	}
	opts = notation.VerifyOptions{ArtifactReference: mock.SampleArtifactUri, SignatureMediaType: "application/jose+json"}
	trustPolicy, err = (&policyDocument).GetApplicableTrustPolicy(opts.ArtifactReference)
	if err != nil {
		t.Fatalf("cannot get trustPolicy")
	}
	verificationLevel, _ = trustPolicy.SignatureVerification.GetVerificationLevel()
	outcome = &notation.VerificationOutcome{
		VerificationResults: []*notation.ValidationResult{},
		VerificationLevel:   verificationLevel,
	}
	_, outcome, err = v.Verify(context.Background(), pluginSigEnv, opts)
	if err == nil || outcome.Error == nil || outcome.Error.Error() != "verification plugin \"plugin-name\" returned unexpected response : \"invalid plugin response\"" {
		t.Fatalf("verification should fail when the verification plugin returns unexpected response. error : %v", outcome.Error)
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

	v = verifier{
		trustPolicyDoc: &policyDocument,
		pluginManager:  pluginManager,
	}
	opts = notation.VerifyOptions{ArtifactReference: mock.SampleArtifactUri, SignatureMediaType: "application/jose+json"}
	_, outcome, err = v.Verify(context.Background(), pluginSigEnv, opts)
	if err == nil || outcome.Error == nil || outcome.Error.Error() != "extended critical attribute \"SomeKey\" was not processed by the verification plugin \"plugin-name\" (all extended critical attributes must be processed by the verification plugin)" {
		t.Fatalf("verification should fail when the verification plugin fails to process an extended critical attribute. error : %v", outcome.Error)
	}

	// plugin returned empty result for a capability
	pluginManager = mock.PluginManager{}
	pluginManager.PluginCapabilities = []plugin.Capability{plugin.CapabilityTrustedIdentityVerifier}
	pluginManager.PluginRunnerExecuteResponse = &plugin.VerifySignatureResponse{
		VerificationResults: map[plugin.VerificationCapability]*plugin.VerificationResult{},
		ProcessedAttributes: []interface{}{mock.PluginExtendedCriticalAttribute.Key},
	}

	v = verifier{
		trustPolicyDoc: &policyDocument,
		pluginManager:  pluginManager,
	}
	opts = notation.VerifyOptions{ArtifactReference: mock.SampleArtifactUri, SignatureMediaType: "application/jose+json"}
	_, outcome, err = v.Verify(context.Background(), pluginSigEnv, opts)
	if err == nil || outcome.Error == nil || outcome.Error.Error() != "verification plugin \"plugin-name\" failed to verify \"SIGNATURE_VERIFIER.TRUSTED_IDENTITY\"" {
		t.Fatalf("verification should fail when the verification plugin does not return response for a capability. error : %v", outcome.Error)
	}
}
