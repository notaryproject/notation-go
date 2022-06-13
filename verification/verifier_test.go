package verification

import (
	"strconv"
	"testing"

	corex509 "github.com/notaryproject/notation-core-go/x509"
)

func TestVerifyX509TrustedIdentities(t *testing.T) {

	certs, _ := corex509.ReadCertificateFile("testdata/verifier/signing-cert.pem")

	tests := []struct {
		x509Identities []string
		wantErr        bool
	}{
		{[]string{"x509.subject:C=US,O=SomeOrg,ST=WA"}, false},
		{[]string{"x509.subject:C=US,O=SomeOrg,ST=WA", "nonX509Prefix:my-custom-identity"}, false},
		{[]string{"x509.subject:C=US,O=SomeOrg,ST=WA", "x509.subject:C=IND,O=SomeOrg,ST=TS"}, false},
		{[]string{"nonX509Prefix:my-custom-identity"}, false},
		{[]string{"*"}, false},
		{[]string{"x509.subject:C=IND,O=SomeOrg,ST=TS"}, true},
		{[]string{"x509.subject:C=IND,O=SomeOrg,ST=TS", "nonX509Prefix:my-custom-identity"}, true},
		{[]string{"x509.subject:C=IND,O=SomeOrg,ST=TS", "x509.subject:C=LOL,O=LOL,ST=LOL"}, true},
	}
	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			trustPolicy := TrustPolicy{
				Name:                  "test-statement-name",
				RegistryScopes:        []string{"registry.acme-rockets.io/software/net-monitor"},
				SignatureVerification: "strict",
				TrustStore:            "ca:test-store",
				TrustedIdentities:     tt.x509Identities,
			}
			err := verifyX509TrustedIdentities(certs, trustPolicy)

			if tt.wantErr != (err != nil) {
				t.Fatalf("TestVerifyX509TrustedIdentities Error: %q WantErr: %v", err, tt.wantErr)
			}
		})
	}
}
