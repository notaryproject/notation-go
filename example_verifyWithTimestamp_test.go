// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package notation_test

import (
	"context"
	"fmt"
	"os"

	_ "github.com/notaryproject/notation-core-go/signature/cose"
	_ "github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	"oras.land/oras-go/v2/registry/remote"
)

// Example_verifyWithTimestamp demonstrates how to use notation.Verify to verify
// signature of an artifact including RFC 3161 compliant timestamp countersignature
func Example_verifyWithTimestamp() {
	// exampleArtifactReference is an example of the target artifact reference
	exampleArtifactReference := "localhost:5000/software@sha256:60043cf45eaebc4c0867fea485a039b598f52fd09fd5b07b0b2d2f88fad9d74e"

	// examplePolicyDocument is an example of a valid trust policy document with
	// timestamping configurations.
	// trust policy document should follow this spec:
	// https://github.com/notaryproject/notaryproject/blob/v1.0.0/specs/trust-store-trust-policy.md#trust-policy
	examplePolicyDocument := trustpolicy.Document{
		Version: "1.0",
		TrustPolicies: []trustpolicy.TrustPolicy{
			{
				Name:           "test-statement-name",
				RegistryScopes: []string{"*"},
				SignatureVerification: trustpolicy.SignatureVerification{
					VerificationLevel: trustpolicy.LevelStrict.Name,

					// verify timestamp countersignature only if the signing
					// certificate chain has expired.
					// Default: trustpolicy.OptionAlways
					VerifyTimestamp: trustpolicy.OptionAfterCertExpiry,

					// verify timestamp countersignature but skip timestamp
					// certificate chain revocation check.
					// Default: false
					SkipTimestampRevocationCheck: true,
				},

				// `tsa` trust store type MUST be configured to enable
				// timestamp verification
				TrustStores: []string{"ca:valid-trust-store", "tsa:valid-tsa"},

				// TrustedIdentities only contains trusted identities of `ca`
				// and `signingAuthority`
				TrustedIdentities: []string{"*"},
			},
		},
	}

	// generateTrustStoreWithTimestamp generates a trust store directory for demo purpose.
	// Users should configure their own trust store and add trusted certificates
	// into it following the trust store spec:
	// https://github.com/notaryproject/notaryproject/blob/v1.0.0/specs/trust-store-trust-policy.md#trust-store
	if err := generateTrustStoreWithTimestamp(); err != nil {
		panic(err) // Handle error
	}

	// exampleVerifier is an example of notation.Verifier given
	// trust policy document and X509 trust store.
	exampleVerifier, err := verifier.New(&examplePolicyDocument, truststore.NewX509TrustStore(dir.ConfigFS()), nil)
	if err != nil {
		panic(err) // Handle error
	}

	// exampleRepo is an example of registry.Repository.
	remoteRepo, err := remote.NewRepository(exampleArtifactReference)
	if err != nil {
		panic(err) // Handle error
	}
	exampleRepo := registry.NewRepository(remoteRepo)

	// exampleVerifyOptions is an example of notation.VerifyOptions.
	exampleVerifyOptions := notation.VerifyOptions{
		ArtifactReference:    exampleArtifactReference,
		MaxSignatureAttempts: 50,
	}

	// remote verify core process
	// upon successful verification, the target manifest descriptor
	// and signature verification outcome are returned.
	targetDesc, _, err := notation.Verify(context.Background(), exampleVerifier, exampleRepo, exampleVerifyOptions)
	if err != nil {
		panic(err) // Handle error
	}

	fmt.Println("Successfully verified")
	fmt.Println("targetDesc MediaType:", targetDesc.MediaType)
	fmt.Println("targetDesc Digest:", targetDesc.Digest)
	fmt.Println("targetDesc Size:", targetDesc.Size)
}

func generateTrustStoreWithTimestamp() error {
	// changing the path of the trust store for demo purpose.
	// Users could keep the default value, i.e. os.UserConfigDir.
	dir.UserConfigDir = "tmp"

	// an example of a valid X509 self-signed certificate for demo purpose ONLY.
	// Users should replace `exampleX509Certificate` with their own trusted
	// certificate and add to the trust store, following the
	// Notary certificate requirements:
	// https://github.com/notaryproject/notaryproject/blob/v1.0.0/specs/signature-specification.md#certificate-requirements
	exampleX509Certificate := `-----BEGIN CERTIFICATE-----
MIIDQDCCAiigAwIBAgIBUTANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJVUzEL
MAkGA1UECBMCV0ExEDAOBgNVBAcTB1NlYXR0bGUxDzANBgNVBAoTBk5vdGFyeTEP
MA0GA1UEAxMGYWxwaW5lMCAXDTAwMDgyOTEzNTAwMFoYDzIxMjMwODI5MTM1MDAw
WjBOMQswCQYDVQQGEwJVUzELMAkGA1UECBMCV0ExEDAOBgNVBAcTB1NlYXR0bGUx
DzANBgNVBAoTBk5vdGFyeTEPMA0GA1UEAxMGYWxwaW5lMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAocg3qEsyNDDLfB8OHD4dhi+M1NPK1Asy5NX84c+g
vacZuoPLTwmpOfm6nPt7GPPB9G7S6xxhFNbRxTYfYUjK+kaCj38XjBRf5lGewbSJ
KVkxQ82/axU70ceSW3JpazrageN9JUTZ/Jfi4MfnipITwcmMoiij8eGrHskjyVyZ
bJd0WMMKRDWVhLPUiPMVWt/4d7YtZItzacaQKtXmXgsTCTWpIols3gftNYjrQoMs
UelUdD8vOAWN9J28/SyC+uSh/K1KfyUlbqufn4di8DEBxntP5wnXYbJL1jtjsUgE
xAVjQxT1zI59X36m3t3YKqCQh1cud02L5onObY6zj57N6QIDAQABoycwJTAOBgNV
HQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwDQYJKoZIhvcNAQELBQAD
ggEBAC8AjBLy7EsRpi6oguCdFSb6nRGjvF17N+b6mDb3sARnB8T1pxvzTT26ya+A
yWR+jjodEwbMIS+13lV+9qT2LwqlbOUNY519Pa2GRRY72JjeowWI3iKkKaMzfZUB
7lRTGXdEuZApLbTO/3JVcR9ffu00N1UaAP9YGElSt4JDJYA9M+d/Qto+HiIsE0Kj
+jdnwIYovPPOlryKOLfFb/r1GEq7n63xFZz83iyWNaZdsJ5N3YHxdOpkbBbCalOE
BDJTjQKqeAYBLoANNU0OBslmqHCSBTEnhbqJHN6QKyF09ScOl5LwM1QsTl0UY5si
GLAfj/jSf9OH9VLTPHOS8/N0Ka4=
-----END CERTIFICATE-----`

	// Adding the certificate into the trust store.
	if err := os.MkdirAll("tmp/truststore/x509/ca/valid-trust-store", 0700); err != nil {
		return err
	}
	if err := os.WriteFile("tmp/truststore/x509/ca/valid-trust-store/NotationExample.pem", []byte(exampleX509Certificate), 0600); err != nil {
		return err
	}

	// an example of a valid TSA root certificate for demo purpose ONLY.
	// Users should replace `exampleTSARootCertificate` with their own trusted
	// TSA root certificate and add to the trust store, following the
	// Notary certificate requirements:
	// https://github.com/notaryproject/notaryproject/blob/v1.0.0/specs/signature-specification.md#certificate-requirements
	exampleTSARootCertificate := `-----BEGIN CERTIFICATE-----
		MIIFkDCCA3igAwIBAgIQBZsbV56OITLiOQe9p3d1XDANBgkqhkiG9w0BAQwFADBi
		MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
		d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3Qg
		RzQwHhcNMTMwODAxMTIwMDAwWhcNMzgwMTE1MTIwMDAwWjBiMQswCQYDVQQGEwJV
		UzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQu
		Y29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwggIiMA0GCSqG
		SIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz7MKnJS7JIT3y
		ithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS5F/WBTxSD1If
		xp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7bXHiLQwb7iDV
		ySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfISKhmV1efVFiO
		DCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jHtrHEtWoYOAMQ
		jdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14Ztk6MUSaM0C/
		CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCi
		EhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt6zPZxd9LBADM
		fRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QY
		uKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ERElvlEFDrMcXK
		chYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4KJpn15GkvmB0t
		9dmpsh3lGwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIB
		hjAdBgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wDQYJKoZIhvcNAQEMBQAD
		ggIBALth2X2pbL4XxJEbw6GiAI3jZGgPVs93rnD5/ZpKmbnJeFwMDF/k5hQpVgs2
		SV1EY+CtnJYYZhsjDT156W1r1lT40jzBQ0CuHVD1UvyQO7uYmWlrx8GnqGikJ9yd
		+SeuMIW59mdNOj6PWTkiU0TryF0Dyu1Qen1iIQqAyHNm0aAFYF/opbSnr6j3bTWc
		fFqK1qI4mfN4i/RN0iAL3gTujJtHgXINwBQy7zBZLq7gcfJW5GqXb5JQbZaNaHqa
		sjYUegbyJLkJEVDXCLG4iXqEI2FCKeWjzaIgQdfRnGTZ6iahixTXTBmyUEFxPT9N
		cCOGDErcgdLMMpSEDQgJlxxPwO5rIHQw0uA5NBCFIRUBCOhVMt5xSdkoF1BN5r5N
		0XWs0Mr7QbhDparTwwVETyw2m+L64kW4I1NsBm9nVX9GtUw/bihaeSbSpKhil9Ie
		4u1Ki7wb/UdKDd9nZn6yW0HQO+T0O/QEY+nvwlQAUaCKKsnOeMzV6ocEGLPOr0mI
		r/OSmbaz5mEP0oUA51Aa5BuVnRmhuZyxm7EAHu/QD09CbMkKvO5D+jpxpchNJqU1
		/YldvIViHTLSoCtU7ZpXwdv6EM8Zt4tKG48BtieVU+i2iW1bvGjUI+iLUaJW+fCm
		gKDWHrO8Dw9TdSmq6hN35N6MgSGtBxBHEa2HPQfRdbzP82Z+
		-----END CERTIFICATE-----`

	// Adding the tsa root certificate into the trust store.
	if err := os.MkdirAll("tmp/truststore/x509/tsa/valid-tsa", 0700); err != nil {
		return err
	}
	return os.WriteFile("tmp/truststore/x509/tsa/valid-tsa/NotationTSAExample.pem", []byte(exampleTSARootCertificate), 0600)
}
