package verifier

import (
	"errors"
	"path/filepath"
	"strconv"
	"testing"

	corex509 "github.com/notaryproject/notation-core-go/x509"
	"github.com/notaryproject/notation-go/notation"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
)

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
