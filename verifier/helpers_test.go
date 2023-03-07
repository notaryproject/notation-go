package verifier

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/notaryproject/notation-core-go/signature"
	corex509 "github.com/notaryproject/notation-core-go/x509"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
)

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

func dummyPolicyDocument() (policyDoc trustpolicy.Document) {
	policyDoc = trustpolicy.Document{
		Version:       "1.0",
		TrustPolicies: []trustpolicy.TrustPolicy{dummyPolicyStatement()},
	}
	return
}

func TestGetArtifactDigestFromUri(t *testing.T) {

	tests := []struct {
		artifactReference string
		digest            string
		wantErr           bool
	}{
		{"domain.com/repository@sha256:digest", "sha256:digest", false},
		{"domain.com:80/repository:digest", "", true},
		{"domain.com/repository", "", true},
		{"domain.com/repository@sha256", "", true},
		{"domain.com/repository@sha256:", "", true},
		{"", "", true},
		{"domain.com", "", true},
	}
	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			digest, err := getArtifactDigestFromReference(tt.artifactReference)

			if tt.wantErr != (err != nil) {
				t.Fatalf("TestGetArtifactDigestFromUri Error: %q WantErr: %v Input: %q", err, tt.wantErr, tt.artifactReference)
			} else if digest != tt.digest {
				t.Fatalf("TestGetArtifactDigestFromUri Want: %q Got: %v", tt.digest, digest)
			}
		})
	}
}

func TestLoadX509TrustStore(t *testing.T) {
	// load "ca" and "signingAuthority" trust store
	caStore := "ca:valid-trust-store"
	signingAuthorityStore := "signingAuthority:valid-trust-store"
	dummyPolicy := dummyPolicyStatement()
	dummyPolicy.TrustStores = []string{caStore, signingAuthorityStore}
	dir.UserConfigDir = "testdata"
	x509truststore := truststore.NewX509TrustStore(dir.ConfigFS())
	caCerts, err := loadX509TrustStores(context.Background(), signature.SigningSchemeX509, &dummyPolicy, x509truststore)
	if err != nil {
		t.Fatalf("TestLoadX509TrustStore should not throw error for a valid trust store. Error: %v", err)
	}
	saCerts, err := loadX509TrustStores(context.Background(), signature.SigningSchemeX509SigningAuthority, &dummyPolicy, x509truststore)
	if err != nil {
		t.Fatalf("TestLoadX509TrustStore should not throw error for a valid trust store. Error: %v", err)
	}
	if len(caCerts) != 4 || len(saCerts) != 3 {
		t.Fatalf("ca store should have 4 certs and signingAuthority store should have 3 certs")
	}
}

func TestIsCriticalFailure(t *testing.T) {
	var dummyError = errors.New("critical failure")
	tests := []struct {
		result          notation.ValidationResult
		criticalFailure bool
	}{
		{notation.ValidationResult{Action: trustpolicy.ActionEnforce, Error: dummyError}, true},
		{notation.ValidationResult{Action: trustpolicy.ActionLog, Error: dummyError}, false},
		{notation.ValidationResult{Action: trustpolicy.ActionSkip, Error: dummyError}, false},
	}
	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			endResult := isCriticalFailure(&tt.result)

			if endResult != tt.criticalFailure {
				t.Fatalf("TestIsCriticalFailure Expected: %v Got: %v", tt.criticalFailure, endResult)
			}
		})
	}
}

// TestValidCerts tests valid trust store cert
func TestValidateCerts(t *testing.T) {
	joinedPath := filepath.FromSlash("./testdata/truststore/x509/ca/valid-trust-store/GlobalSign.der")
	certs, err := corex509.ReadCertificateFile(joinedPath)
	if err != nil {
		t.Fatalf("error while reading certificates from %q: %q", joinedPath, err)
	}
	err = ValidateCerts(certs)
	if err != nil {
		t.Fatalf("expected to get nil err, but got %q", err)
	}
}

// TestValidateCertsWithLeafCert tests invalid trust store leaf cert
func TestValidateCertsWithLeafCert(t *testing.T) {
	failurePath := filepath.FromSlash("./testdata/truststore/x509/ca/trust-store-with-leaf-certs/non-ca.crt")
	certs, err := corex509.ReadCertificateFile(failurePath)
	if err != nil {
		t.Fatalf("error while reading certificates from %q: %q", failurePath, err)
	}
	expectedErr := errors.New("certificate with subject \"CN=wabbit-networks.io,O=Notary,L=Seattle,ST=WA,C=US\" is not a CA certificate or self-signed signing certificate")
	err = ValidateCerts(certs)
	if err == nil || err.Error() != expectedErr.Error() {
		t.Fatalf("leaf cert in a trust store should return error %q, but got %q", expectedErr, err)
	}
}

func getArtifactDigestFromReference(artifactReference string) (string, error) {
	invalidUriErr := fmt.Errorf("artifact URI %q could not be parsed, make sure it is the fully qualified OCI artifact URI without the scheme/protocol. e.g domain.com:80/my/repository@sha256:digest", artifactReference)
	i := strings.LastIndex(artifactReference, "@")
	if i < 0 || i+1 == len(artifactReference) {
		return "", invalidUriErr
	}

	j := strings.LastIndex(artifactReference[i+1:], ":")
	if j < 0 || j+1 == len(artifactReference[i+1:]) {
		return "", invalidUriErr
	}

	return artifactReference[i+1:], nil
}
