package verifier

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/testhelper"
	corex509 "github.com/notaryproject/notation-core-go/x509"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/internal/mock"
	"github.com/notaryproject/notation-go/log"
	"github.com/notaryproject/notation-go/plugin/proto"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/crypto/ocsp"

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
		expectedErr := fmt.Errorf("error while loading the trust store, trust policy statement \"test-statement-name\" is missing separator in trust store value \"signingAuthority\". The required format is <TrustStoreType>:<TrustStoreName>")
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

func createMockOutcome(certChain []*x509.Certificate) *notation.VerificationOutcome {
	return &notation.VerificationOutcome{
		EnvelopeContent: &signature.EnvelopeContent{
			SignerInfo: signature.SignerInfo{
				SignedAttributes: signature.SignedAttributes{
					SigningTime: time.Now(),
				},
				CertificateChain: certChain,
			},
		},
		VerificationLevel: &trustpolicy.VerificationLevel{
			Enforcement: map[trustpolicy.ValidationType]trustpolicy.ValidationAction{trustpolicy.TypeRevocation: trustpolicy.ActionEnforce},
		},
	}
}

func TestVerifyRevocation(t *testing.T) {
	logger := log.GetLogger(context.Background())

	revokableTuples := testhelper.GetRevokableRSAChain(3)
	revokableChain := []*x509.Certificate{revokableTuples[0].Cert, revokableTuples[1].Cert, revokableTuples[2].Cert}

	goodClient := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
	revokedClient := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Revoked}, nil, true)
	unknownClient := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Unknown}, nil, true)
	pkixNoCheckClient := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Unknown}, nil, false)
	timeoutClient := &http.Client{Timeout: 1 * time.Nanosecond}

	t.Run("verifyRevocation non-revoked", func(t *testing.T) {
		result := verifyRevocation(createMockOutcome(revokableChain), goodClient, logger)
		if result.Error != nil {
			t.Fatalf("expected verifyRevocation to succeed, but got %v", result.Error)
		}
	})
	t.Run("verifyRevocation OCSP revoked", func(t *testing.T) {
		result := verifyRevocation(createMockOutcome(revokableChain), revokedClient, logger)
		expectedMsg := "certificate is revoked via OCSP"
		if result.Error == nil || result.Error.Error() != expectedMsg {
			t.Fatalf("expected verifyRevocation to fail with %s, but got %v", expectedMsg, result.Error)
		}
	})
	t.Run("verifyRevocation OCSP unknown", func(t *testing.T) {
		result := verifyRevocation(createMockOutcome(revokableChain), unknownClient, logger)
		expectedMsg := "certificate has unknown status via OCSP"
		if result.Error == nil || result.Error.Error() != expectedMsg {
			t.Fatalf("expected verifyRevocation to fail with %s, but got %v", expectedMsg, result.Error)
		}
	})
	t.Run("verifyRevocation missing id-pkix-ocsp-nocheck", func(t *testing.T) {
		result := verifyRevocation(createMockOutcome(revokableChain), pkixNoCheckClient, logger)
		if result.Error != nil {
			t.Fatalf("expected verifyRevocation to succeed, but got %v", result.Error)
		}
	})
	t.Run("verifyRevocation timeout", func(t *testing.T) {
		result := verifyRevocation(createMockOutcome(revokableChain), timeoutClient, logger)
		expectedMsg := fmt.Sprintf("exceeded timeout threshold of %.2f seconds for OCSP check", timeoutClient.Timeout.Seconds())
		if result.Error == nil || result.Error.Error() != expectedMsg {
			t.Fatalf("expected verifyRevocation to fail with %s, but got %v", expectedMsg, result.Error)
		}
	})
}

func TestNewWithRevocationClient(t *testing.T) {
	policy := dummyPolicyDocument()
	store := truststore.NewX509TrustStore(dir.ConfigFS())
	pm := mock.PluginManager{}
	client := &http.Client{Timeout: 2 * time.Second}
	v, err := NewWithRevocationClient(&policy, store, pm, client)

	if err != nil {
		t.Fatalf("expected NewWithRevocationClient constructor to succeed, but got %v", err)
	}

	expectedV := &verifier{
		trustPolicyDoc:   &policy,
		trustStore:       store,
		pluginManager:    pm,
		revocationClient: client,
	}
	if !reflect.DeepEqual(expectedV, v) {
		t.Fatalf("expected %v to be created, but got %v", expectedV, v)
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

	certs, _ := corex509.ReadCertificateFile(filepath.FromSlash("testdata/verifier/signing-cert.pem"))        // cert's subject is "CN=SomeCN,OU=SomeOU,O=SomeOrg,L=Seattle,ST=WA,C=US"
	unsupportedCerts, _ := corex509.ReadCertificateFile(filepath.FromSlash("testdata/verifier/bad-cert.pem")) // cert's subject is "CN=bad=#CN,OU=SomeOU,O=SomeOrg,L=Seattle,ST=WA,C=US"

	tests := []struct {
		certs          []*x509.Certificate
		x509Identities []string
		wantErr        bool
	}{
		{certs, []string{"x509.subject:C=US,O=SomeOrg,ST=WA"}, false},
		{certs, []string{"x509.subject:C=US,O=SomeOrg,ST=WA", "nonX509Prefix:my-custom-identity"}, false},
		{certs, []string{"x509.subject:C=US,O=SomeOrg,ST=WA", "x509.subject:C=IND,O=SomeOrg,ST=TS"}, false},
		{certs, []string{"nonX509Prefix:my-custom-identity"}, true},
		{certs, []string{"*"}, false},
		{certs, []string{"x509.subject:C=IND,O=SomeOrg,ST=TS"}, true},
		{certs, []string{"x509.subject:C=IND,O=SomeOrg,ST=TS", "nonX509Prefix:my-custom-identity"}, true},
		{certs, []string{"x509.subject:C=IND,O=SomeOrg,ST=TS", "x509.subject:C=LOL,O=LOL,ST=LOL"}, true},
		{certs, []string{"x509.subject:C=bad=#identity,O=LOL,ST=LOL"}, true},
		{unsupportedCerts, []string{"x509.subject:C=US,O=SomeOrg,ST=WA", "nonX509Prefix:my-custom-identity"}, true},
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
			err := verifyX509TrustedIdentities(tt.certs, &trustPolicy)

			if tt.wantErr != (err != nil) {
				t.Fatalf("TestVerifyX509TrustedIdentities Error: %q WantErr: %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyUserMetadata(t *testing.T) {
	policyDocument := dummyPolicyDocument()
	policyDocument.TrustPolicies[0].SignatureVerification.VerificationLevel = trustpolicy.LevelAudit.Name

	pluginManager := mock.PluginManager{}
	pluginManager.GetPluginError = errors.New("plugin should not be invoked when verification plugin is not specified in the signature")
	pluginManager.PluginRunnerLoadError = errors.New("plugin should not be invoked when verification plugin is not specified in the signature")

	verifier := verifier{
		trustPolicyDoc: &policyDocument,
		trustStore:     truststore.NewX509TrustStore(dir.ConfigFS()),
		pluginManager:  pluginManager,
	}

	tests := []struct {
		metadata map[string]string
		wantErr  bool
	}{
		{map[string]string{}, false},
		{map[string]string{"io.wabbit-networks.buildId": "123"}, false},
		{map[string]string{"io.wabbit-networks.buildId": "321"}, true},
		{map[string]string{"io.wabbit-networks.buildId": "123", "io.wabbit-networks.buildTime": "1672944615"}, false},
		{map[string]string{"io.wabbit-networks.buildId": "123", "io.wabbit-networks.buildTime": "1"}, true},
	}

	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			_, err := verifier.Verify(
				context.Background(),
				mock.MetadataSigEnvDescriptor,
				mock.MockSigEnvWithMetadata,
				notation.VerifyOptions{
					ArtifactReference:  mock.SampleArtifactUri,
					SignatureMediaType: "application/jose+json",
					UserMetadata:       tt.metadata,
				},
			)

			if tt.wantErr != (err != nil) {
				t.Fatalf("TestVerifyUserMetadata Error: %q WantErr: %v", err, tt.wantErr)
			}
		})
	}
}

func TestPluginVersionCompatibility(t *testing.T) {

	errTemplate := "found plugin io.cncf.notary.plugin.unittest.mock with version 1.0.0 but signature verification needs plugin version greater than or equal to "
	var policyDocument = trustpolicy.Document{
		Version: "1.0",
		TrustPolicies: []trustpolicy.TrustPolicy{
			{
				Name:                  "wabbit-networks-images",
				RegistryScopes:        []string{"localhost:5000/net-monitor"},
				SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: trustpolicy.LevelStrict.Name},
				TrustStores:           []string{"ca:valid-trust-store"},
				TrustedIdentities:     []string{"x509.subject: CN=wabbit-networks.io,O=Notary,L=Seattle,ST=WA,C=US"},
			},
		},
	}
	pluginManager := mock.PluginManager{}
	pluginManager.PluginCapabilities = []proto.Capability{proto.CapabilityTrustedIdentityVerifier}
	pluginManager.PluginRunnerExecuteResponse = &proto.VerifySignatureResponse{
		VerificationResults: map[proto.Capability]*proto.VerificationResult{
			proto.CapabilityTrustedIdentityVerifier: {
				Success: true,
			},
		},
		ProcessedAttributes: []interface{}{mock.PluginExtendedCriticalAttribute.Key},
	}
	dir.UserConfigDir = "testdata"
	x509TrustStore := truststore.NewX509TrustStore(dir.ConfigFS())
	v := verifier{
		trustPolicyDoc: &policyDocument,
		trustStore:     x509TrustStore,
		pluginManager:  pluginManager,
	}
	opts := notation.VerifyOptions{ArtifactReference: "localhost:5000/net-monitor@sha256:fe7e9333395060c2f5e63cf36a38fba10176f183b4163a5794e081a480abba5f", SignatureMediaType: "application/jose+json"}

	tests := []struct {
		minPluginVerTests []byte
		wantErr           string
	}{

		{mock.MockCaIncompatiblePluginVerSigEnv_1_0_9, errTemplate + "1.0.9"},
		{mock.MockCaIncompatiblePluginVerSigEnv_1_0_1, errTemplate + "1.0.1"},
		{mock.MockCaIncompatiblePluginVerSigEnv_1_2_3, errTemplate + "1.2.3"},
		{mock.MockCaIncompatiblePluginVerSigEnv_1_1_0_alpha, errTemplate + "1.1.0-alpha"},
		{mock.MockCaCompatiblePluginVerSigEnv_0_0_9, ""},
		{mock.MockCaCompatiblePluginVerSigEnv_1_0_0_alpha, ""},
		{mock.MockCaCompatiblePluginVerSigEnv_1_0_0_alpha_beta, ""},
		{mock.MockCaCompatiblePluginVerSigEnv_1_0_0, ""},
	}
	for _, tt := range tests {

		if _, err := v.Verify(context.Background(), mock.TestImageDescriptor, tt.minPluginVerTests, opts); err != nil && tt.wantErr != "" {
			if err.Error() != tt.wantErr {
				t.Errorf("TestPluginVersionCompatibility Error: %s, WantErr: %s ", err.Error(), tt.wantErr)
			}
		}
	}
}

func TestIsRequiredVerificationPluginVer(t *testing.T) {

	testPlugVer := "1.0.0"

	tests := []struct {
		minVerTests []string
		expectedVal bool
	}{
		{[]string{"0.0.9"}, true},
		{[]string{"1.0.0"}, true},
		{[]string{"1.0.0-alpha"}, true},
		{[]string{"1-pre+meta"}, true},
		{[]string{"1.0.1"}, false},
		{[]string{"1.1.0"}, false},
		{[]string{"1.2.0"}, false},
		{[]string{"1.1.0-alpha"}, false},
	}
	for _, tt := range tests {
		funcVal := isRequiredVerificationPluginVer(testPlugVer, tt.minVerTests[0])
		if funcVal != tt.expectedVal {
			t.Errorf("TestIsRequiredVerificationPluginVer Error: version comparison mismatch between plugin with version %s and min verification plugin version %s, function output: %v, expected output: %v", testPlugVer, tt.minVerTests[0], funcVal, tt.expectedVal)
		}
	}
}
