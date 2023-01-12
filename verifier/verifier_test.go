package verifier

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/notaryproject/notation-core-go/signature"
	corex509 "github.com/notaryproject/notation-core-go/x509"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/internal/mock"
	"github.com/notaryproject/notation-go/plugin/proto"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

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

func TestNewVerifier_Error(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	_, err := New(&policyDocument, nil, nil)
	expectedErr := errors.New("trustPolicy or trustStore cannot be nil")
	if err == nil || err.Error() != expectedErr.Error() {
		t.Fatalf("TestNewVerifier_Error expected error %v, got %v", expectedErr, err)
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
			_, err := verifier.Verify(context.Background(), ocispec.Descriptor{}, []byte{}, opts)
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
	_, err := verifier.Verify(context.Background(), ocispec.Descriptor{}, []byte{}, opts)
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

	// Authenticity Failure with trust store missing separator
	for _, level := range verificationLevels {
		policyDocument := dummyPolicyDocument()
		policyDocument.TrustPolicies[0].TrustStores = []string{"ca:valid-trust-store-2", "signingAuthority"}
		expectedErr := fmt.Errorf("error while loading the trust store, trust policy statement \"test-statement-name\" is missing separator in trust store value \"signingAuthority\"")
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

	// TrustedIdentity Failure without separator
	for _, level := range verificationLevels {
		policyDocument := dummyPolicyDocument()
		policyDocument.TrustPolicies[0].TrustedIdentities = []string{"x509.subject"}
		expectedErr := fmt.Errorf("trust policy statement \"test-statement-name\" has trusted identity \"x509.subject\" missing separator")
		testCases = append(testCases, testCase{
			signatureBlob:     validSigEnv,
			verificationType:  trustpolicy.TypeAuthenticity,
			verificationLevel: level,
			policyDocument:    policyDocument,
			opts:              notation.VerifyOptions{ArtifactReference: mock.SampleArtifactUri, SignatureMediaType: "application/jose+json"},
			expectedErr:       expectedErr,
		})
	}

	// TrustedIdentity Failure with empty value
	for _, level := range verificationLevels {
		policyDocument := dummyPolicyDocument()
		policyDocument.TrustPolicies[0].TrustedIdentities = []string{"x509.subject:"}
		expectedErr := fmt.Errorf("trust policy statement \"test-statement-name\" has trusted identity \"x509.subject:\" without an identity value")
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
				trustStore:     truststore.NewX509TrustStore(dir.ConfigFS()),
				pluginManager:  pluginManager,
			}
			outcome, _ := verifier.Verify(context.Background(), ocispec.Descriptor{}, tt.signatureBlob, tt.opts)
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
	x509TrustStore := truststore.NewX509TrustStore(dir.ConfigFS())

	// verification plugin is not installed
	pluginManager := mock.PluginManager{}
	pluginManager.GetPluginError = errors.New("plugin not found")

	v := verifier{
		trustPolicyDoc: &policyDocument,
		trustStore:     x509TrustStore,
		pluginManager:  pluginManager,
	}
	opts := notation.VerifyOptions{ArtifactReference: mock.SampleArtifactUri, SignatureMediaType: "application/jose+json"}
	outcome, err := v.Verify(context.Background(), ocispec.Descriptor{}, pluginSigEnv, opts)
	if err == nil || outcome.Error == nil || outcome.Error.Error() != "error while locating the verification plugin \"plugin-name\", make sure the plugin is installed successfully before verifying the signature. error: plugin not found" {
		t.Fatalf("verification should fail if the verification plugin is not found")
	}

	// plugin is installed but without verification capabilities
	pluginManager = mock.PluginManager{}
	pluginManager.PluginCapabilities = []proto.Capability{proto.CapabilitySignatureGenerator}

	v = verifier{
		trustPolicyDoc: &policyDocument,
		trustStore:     x509TrustStore,
		pluginManager:  pluginManager,
	}
	opts = notation.VerifyOptions{ArtifactReference: mock.SampleArtifactUri, SignatureMediaType: "application/jose+json"}
	outcome, err = v.Verify(context.Background(), ocispec.Descriptor{}, pluginSigEnv, opts)
	if err == nil || outcome.Error == nil || outcome.Error.Error() != "digital signature requires plugin \"plugin-name\" with signature verification capabilities (\"SIGNATURE_VERIFIER.TRUSTED_IDENTITY\" and/or \"SIGNATURE_VERIFIER.REVOCATION_CHECK\") installed" {
		t.Fatalf("verification should fail if the verification plugin is not found")
	}

	// plugin interactions with trusted identity verification success
	pluginManager = mock.PluginManager{}
	pluginManager.PluginCapabilities = []proto.Capability{proto.CapabilityTrustedIdentityVerifier}
	pluginManager.PluginRunnerExecuteResponse = &proto.VerifySignatureResponse{
		VerificationResults: map[proto.Capability]*proto.VerificationResult{
			proto.CapabilityTrustedIdentityVerifier: {
				Success: true,
			},
		},
		ProcessedAttributes: []interface{}{mock.PluginExtendedCriticalAttribute.Key},
	}

	v = verifier{
		trustPolicyDoc: &policyDocument,
		trustStore:     x509TrustStore,
		pluginManager:  pluginManager,
	}
	opts = notation.VerifyOptions{ArtifactReference: mock.SampleArtifactUri, SignatureMediaType: "application/jose+json"}
	outcome, err = v.Verify(context.Background(), mock.ImageDescriptor, pluginSigEnv, opts)
	if err != nil || outcome.Error != nil {
		t.Fatalf("verification should succeed when the verification plugin succeeds for trusted identity verification. error : %v", outcome.Error)
	}

	// plugin interactions with trusted identity verification failure
	pluginManager = mock.PluginManager{}
	pluginManager.PluginCapabilities = []proto.Capability{proto.CapabilityTrustedIdentityVerifier}
	pluginManager.PluginRunnerExecuteResponse = &proto.VerifySignatureResponse{
		VerificationResults: map[proto.Capability]*proto.VerificationResult{
			proto.CapabilityTrustedIdentityVerifier: {
				Success: false,
				Reason:  "i feel like failing today",
			},
		},
		ProcessedAttributes: []interface{}{mock.PluginExtendedCriticalAttribute.Key},
	}

	v = verifier{
		trustPolicyDoc: &policyDocument,
		trustStore:     x509TrustStore,
		pluginManager:  pluginManager,
	}
	opts = notation.VerifyOptions{ArtifactReference: mock.SampleArtifactUri, SignatureMediaType: "application/jose+json"}
	outcome, err = v.Verify(context.Background(), ocispec.Descriptor{}, pluginSigEnv, opts)
	if err == nil || outcome.Error == nil || outcome.Error.Error() != "trusted identify verification by plugin \"plugin-name\" failed with reason \"i feel like failing today\"" {
		t.Fatalf("verification should fail when the verification plugin fails for trusted identity verification. error : %v", outcome.Error)
	}

	// plugin interactions with revocation verification success
	pluginManager = mock.PluginManager{}
	pluginManager.PluginCapabilities = []proto.Capability{proto.CapabilityRevocationCheckVerifier}
	pluginManager.PluginRunnerExecuteResponse = &proto.VerifySignatureResponse{
		VerificationResults: map[proto.Capability]*proto.VerificationResult{
			proto.CapabilityRevocationCheckVerifier: {
				Success: true,
			},
		},
		ProcessedAttributes: []interface{}{mock.PluginExtendedCriticalAttribute.Key},
	}

	v = verifier{
		trustPolicyDoc: &policyDocument,
		trustStore:     x509TrustStore,
		pluginManager:  pluginManager,
	}
	opts = notation.VerifyOptions{ArtifactReference: mock.SampleArtifactUri, SignatureMediaType: "application/jose+json"}
	outcome, err = v.Verify(context.Background(), mock.ImageDescriptor, pluginSigEnv, opts)
	if err != nil || outcome.Error != nil {
		t.Fatalf("verification should succeed when the verification plugin succeeds for revocation verification. error : %v", outcome.Error)
	}

	// plugin interactions with trusted revocation failure
	pluginManager = mock.PluginManager{}
	pluginManager.PluginCapabilities = []proto.Capability{proto.CapabilityRevocationCheckVerifier}
	pluginManager.PluginRunnerExecuteResponse = &proto.VerifySignatureResponse{
		VerificationResults: map[proto.Capability]*proto.VerificationResult{
			proto.CapabilityRevocationCheckVerifier: {
				Success: false,
				Reason:  "i feel like failing today",
			},
		},
		ProcessedAttributes: []interface{}{mock.PluginExtendedCriticalAttribute.Key},
	}

	v = verifier{
		trustPolicyDoc: &policyDocument,
		trustStore:     x509TrustStore,
		pluginManager:  pluginManager,
	}
	opts = notation.VerifyOptions{ArtifactReference: mock.SampleArtifactUri, SignatureMediaType: "application/jose+json"}
	outcome, err = v.Verify(context.Background(), ocispec.Descriptor{}, pluginSigEnv, opts)
	if err == nil || outcome.Error == nil || outcome.Error.Error() != "revocation check by verification plugin \"plugin-name\" failed with reason \"i feel like failing today\"" {
		t.Fatalf("verification should fail when the verification plugin fails for revocation check verification. error : %v", outcome.Error)
	}

	// plugin interactions with both trusted identity & revocation verification
	pluginManager = mock.PluginManager{}
	pluginManager.PluginCapabilities = []proto.Capability{proto.CapabilityRevocationCheckVerifier, proto.CapabilityTrustedIdentityVerifier}
	pluginManager.PluginRunnerExecuteResponse = &proto.VerifySignatureResponse{
		VerificationResults: map[proto.Capability]*proto.VerificationResult{
			proto.CapabilityRevocationCheckVerifier: {
				Success: true,
			},
			proto.CapabilityTrustedIdentityVerifier: {
				Success: true,
			},
		},
		ProcessedAttributes: []interface{}{mock.PluginExtendedCriticalAttribute.Key},
	}

	v = verifier{
		trustPolicyDoc: &policyDocument,
		trustStore:     x509TrustStore,
		pluginManager:  pluginManager,
	}
	opts = notation.VerifyOptions{ArtifactReference: mock.SampleArtifactUri, SignatureMediaType: "application/jose+json"}
	outcome, err = v.Verify(context.Background(), mock.ImageDescriptor, pluginSigEnv, opts)
	if err != nil || outcome.Error != nil {
		t.Fatalf("verification should succeed when the verification plugin succeeds for both trusted identity and revocation check verifications. error : %v", outcome.Error)
	}

	// plugin interactions with skipped revocation
	policyDocument.TrustPolicies[0].SignatureVerification.Override = map[trustpolicy.ValidationType]trustpolicy.ValidationAction{trustpolicy.TypeRevocation: trustpolicy.ActionSkip}
	pluginManager = mock.PluginManager{}
	pluginManager.PluginCapabilities = []proto.Capability{proto.CapabilityRevocationCheckVerifier}
	pluginManager.PluginRunnerExecuteError = errors.New("revocation plugin should not be invoked when the trust policy skips revocation check")

	v = verifier{
		trustPolicyDoc: &policyDocument,
		trustStore:     x509TrustStore,
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
	outcome, err = v.Verify(context.Background(), mock.ImageDescriptor, pluginSigEnv, opts)
	if err != nil || outcome.Error != nil {
		t.Fatalf("revocation plugin should not be invoked when the trust policy skips the revocation check. error : %v", outcome.Error)
	}

	// plugin unexpected response
	pluginManager = mock.PluginManager{}
	pluginManager.PluginCapabilities = []proto.Capability{proto.CapabilityTrustedIdentityVerifier}
	pluginManager.PluginRunnerExecuteResponse = "invalid plugin response"
	pluginManager.PluginRunnerExecuteError = errors.New("invalid plugin response")

	v = verifier{
		trustPolicyDoc: &policyDocument,
		trustStore:     x509TrustStore,
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
	outcome, err = v.Verify(context.Background(), mock.ImageDescriptor, pluginSigEnv, opts)
	if err == nil || outcome.Error == nil || outcome.Error.Error() != "invalid plugin response" {
		t.Fatalf("verification should fail when the verification plugin returns unexpected response. error : %v", outcome.Error)
	}

	// plugin did not process all extended critical attributes
	pluginManager = mock.PluginManager{}
	pluginManager.PluginCapabilities = []proto.Capability{proto.CapabilityTrustedIdentityVerifier}
	pluginManager.PluginRunnerExecuteResponse = &proto.VerifySignatureResponse{
		VerificationResults: map[proto.Capability]*proto.VerificationResult{
			proto.CapabilityTrustedIdentityVerifier: {
				Success: true,
			},
		},
		ProcessedAttributes: []interface{}{}, // exclude the critical attribute
	}

	v = verifier{
		trustPolicyDoc: &policyDocument,
		trustStore:     x509TrustStore,
		pluginManager:  pluginManager,
	}
	opts = notation.VerifyOptions{ArtifactReference: mock.SampleArtifactUri, SignatureMediaType: "application/jose+json"}
	outcome, err = v.Verify(context.Background(), mock.ImageDescriptor, pluginSigEnv, opts)
	if err == nil || outcome.Error == nil || outcome.Error.Error() != "extended critical attribute \"SomeKey\" was not processed by the verification plugin \"plugin-name\" (all extended critical attributes must be processed by the verification plugin)" {
		t.Fatalf("verification should fail when the verification plugin fails to process an extended critical attribute. error : %v", outcome.Error)
	}

	// plugin returned empty result for a capability
	pluginManager = mock.PluginManager{}
	pluginManager.PluginCapabilities = []proto.Capability{proto.CapabilityTrustedIdentityVerifier}
	pluginManager.PluginRunnerExecuteResponse = &proto.VerifySignatureResponse{
		VerificationResults: map[proto.Capability]*proto.VerificationResult{},
		ProcessedAttributes: []interface{}{mock.PluginExtendedCriticalAttribute.Key},
	}

	v = verifier{
		trustPolicyDoc: &policyDocument,
		trustStore:     x509TrustStore,
		pluginManager:  pluginManager,
	}
	opts = notation.VerifyOptions{ArtifactReference: mock.SampleArtifactUri, SignatureMediaType: "application/jose+json"}
	outcome, err = v.Verify(context.Background(), mock.ImageDescriptor, pluginSigEnv, opts)
	if err == nil || outcome.Error == nil || outcome.Error.Error() != "verification plugin \"plugin-name\" failed to verify \"SIGNATURE_VERIFIER.TRUSTED_IDENTITY\"" {
		t.Fatalf("verification should fail when the verification plugin does not return response for a capability. error : %v", outcome.Error)
	}
}

func TestVerifyX509TrustedIdentities(t *testing.T) {

	certs, _ := corex509.ReadCertificateFile(filepath.FromSlash("testdata/verifier/signing-cert.pem")) // cert's subject is "CN=SomeCN,OU=SomeOU,O=SomeOrg,L=Seattle,ST=WA,C=US"

	tests := []struct {
		x509Identities []string
		wantErr        bool
	}{
		{[]string{"x509.subject:C=US,O=SomeOrg,ST=WA"}, false},
		{[]string{"x509.subject:C=US,O=SomeOrg,ST=WA", "nonX509Prefix:my-custom-identity"}, false},
		{[]string{"x509.subject:C=US,O=SomeOrg,ST=WA", "x509.subject:C=IND,O=SomeOrg,ST=TS"}, false},
		{[]string{"nonX509Prefix:my-custom-identity"}, true},
		{[]string{"*"}, false},
		{[]string{"x509.subject:C=IND,O=SomeOrg,ST=TS"}, true},
		{[]string{"x509.subject:C=IND,O=SomeOrg,ST=TS", "nonX509Prefix:my-custom-identity"}, true},
		{[]string{"x509.subject:C=IND,O=SomeOrg,ST=TS", "x509.subject:C=LOL,O=LOL,ST=LOL"}, true},
	}
	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			trustPolicy := trustpolicy.TrustPolicy{
				Name:                  "test-statement-name",
				RegistryScopes:        []string{"registry.acme-rockets.io/software/net-monitor"},
				SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: "strict"},
				TrustStores:           []string{"ca:test-store"},
				TrustedIdentities:     tt.x509Identities,
			}
			err := verifyX509TrustedIdentities(certs, &trustPolicy)

			if tt.wantErr != (err != nil) {
				t.Fatalf("TestVerifyX509TrustedIdentities Error: %q WantErr: %v", err, tt.wantErr)
			}
		})
	}
}

func TestPluginVersionCompatibility(t *testing.T) {
	var semverSigEnv1 []byte
	var semverSigEnv2 []byte
	var semverSigEnv3 []byte
	var semverSigEnv4 []byte
	var semverSigEnv5 []byte
	var semverSigEnv6 []byte

	semverSigEnv1 = mock.MockCaMinVerSigEnv1
	semverSigEnv2 = mock.MockCaMinVerSigEnv2
	semverSigEnv3 = mock.MockCaMinVerSigEnv3
	semverSigEnv4 = mock.MockCaMinVerSigEnv4
	semverSigEnv5 = mock.MockCaMinVerSigEnv5
	semverSigEnv6 = mock.MockCaMinVerSigEnv6

	policyDocument := dummyPolicyDocument()

	v := verifier{
		trustPolicyDoc: &policyDocument,
		pluginManager:  mock.PluginManager{},
	}
	opts := notation.VerifyOptions{ArtifactReference: mock.SampleArtifactUri, SignatureMediaType: "application/jose+json"}
	envelopeMediaType := opts.SignatureMediaType
	trustPolicy, _ := v.trustPolicyDoc.GetApplicableTrustPolicy(mock.SampleArtifactUri)
	pluginConfig := opts.PluginConfig
	verificationLevel, _ := trustPolicy.SignatureVerification.GetVerificationLevel()

	testSignatureArrHigh := [][]byte{semverSigEnv1, semverSigEnv2, semverSigEnv3}
	testSignatureArrLow := [][]byte{semverSigEnv4, semverSigEnv5, semverSigEnv6}

	for _, testSemSigEnv := range testSignatureArrHigh {
		outcome := &notation.VerificationOutcome{
			RawSignature:      testSemSigEnv,
			VerificationLevel: verificationLevel,
		}
		err := v.processSignature(context.Background(), testSemSigEnv, envelopeMediaType, trustPolicy, pluginConfig, outcome)
		verificationPluginMinVersion, _ := getVerificationPluginMinVersion(&outcome.EnvelopeContent.SignerInfo)
		outcome.Error = err
		var errMsg string = "found plugin io.cncf.notary.plugin.unittest.mock with version 1.0.0 but signature verification needs plugin version greater than or equal to " + verificationPluginMinVersion
		if outcome.Error == nil || outcome.Error.Error() != errMsg {
			t.Errorf("TestPluginVersionCompatibility Error is %s", outcome.Error.Error())
		}
	}

	for _, testSemSigEnv := range testSignatureArrLow {
		outcome := &notation.VerificationOutcome{
			RawSignature:      testSemSigEnv,
			VerificationLevel: verificationLevel,
		}
		err := v.processSignature(context.Background(), testSemSigEnv, envelopeMediaType, trustPolicy, pluginConfig, outcome)
		verificationPluginMinVersion, _ := getVerificationPluginMinVersion(&outcome.EnvelopeContent.SignerInfo)
		outcome.Error = err
		var errMsg string = "found plugin io.cncf.notary.plugin.unittest.mock with version 1.0.0 but signature verification needs plugin version greater than or equal to " + verificationPluginMinVersion
		if outcome.Error.Error() == errMsg {
			t.Errorf("TestPluginVersionCompatibility Error is %s", outcome.Error.Error())
		}
	}
}

func TestIsRequiredVerificationPluginVer(t *testing.T) {

	var testPlugVer string = "1.0.0"

	testArrLow := []string{"0.0.9", "1.0.0", "1.0.0-alpha", "1-pre+meta"}
	testArrHigh := []string{"1.0.1", "1.1.0", "1.1.1", "1.2.0"}

	for _, testMinVer := range testArrLow {
		val := isRequiredVerificationPluginVer(testPlugVer, testMinVer)
		if !val {
			t.Errorf("TestVersionCompare Error: Error with version compare function, version %s has to be higher than %s, but the output is lower, function error: %v WantErr: true", testPlugVer, testMinVer, val)
		}
	}

	for _, testMinVer := range testArrHigh {
		val := isRequiredVerificationPluginVer(testPlugVer, testMinVer)
		if val {
			t.Errorf("TestVersionCompare Error: Error with version compare function, version %s has to be higher than %s, but the output is lower, function error: %v WantErr: true", testMinVer, testPlugVer, val)
		}
	}
}
