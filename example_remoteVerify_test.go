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

// ExampleRemoteVerify demonstrates how to use notation.Verify to verify
// signatures of an artifact in the remote registry.
func Example_remoteVerify() {
	// exampleArtifactReference is an example of the target artifact reference
	exampleArtifactReference := "localhost:5000/software@sha256:60043cf45eaebc4c0867fea485a039b598f52fd09fd5b07b0b2d2f88fad9d74e"

	// examplePolicyDocument is an example of a valid trust policy document.
	// trust policy document should follow this spec:
	// https://github.com/notaryproject/notaryproject/blob/v1.0.0-rc.1/specs/trust-store-trust-policy.md#trust-policy
	examplePolicyDocument := trustpolicy.Document{
		Version: "1.0",
		TrustPolicies: []trustpolicy.TrustPolicy{
			{
				Name:                  "test-statement-name",
				RegistryScopes:        []string{"*"},
				SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: "strict"},
				TrustStores:           []string{"ca:valid-trust-store"},
				TrustedIdentities:     []string{"*"},
			},
		},
	}

	// generateTrustStore creates a trust store directory for demo purpose.
	// Users could use the default trust store from Notary and add trusted
	// certificates into it following the trust store spec:
	// https://github.com/notaryproject/notaryproject/blob/v1.0.0-rc.1/specs/trust-store-trust-policy.md#trust-store
	generateTrustStore()

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

	// exampleRemoteVerifyOptions is an example of notation.RemoteVerifyOptions.
	exampleRemoteVerifyOptions := notation.RemoteVerifyOptions{
		ArtifactReference:    exampleArtifactReference,
		MaxSignatureAttempts: 50,
	}

	// remote verify core process
	// upon successful verification, the target OCI artifact manifest descriptor
	// and signature verification outcome are returned.
	targetDesc, _, err := notation.Verify(context.Background(), exampleVerifier, exampleRepo, exampleRemoteVerifyOptions)
	if err != nil {
		panic(err) // Handle error
	}

	fmt.Println("Successfully verified")
	fmt.Println("targetDesc MediaType:", targetDesc.MediaType)
	fmt.Println("targetDesc Digest:", targetDesc.Digest)
	fmt.Println("targetDesc Size:", targetDesc.Size)
}

func generateTrustStore() {
	// changing the path of the trust store for demo purpose.
	// Users could keep the default value, i.e. os.UserConfigDir.
	dir.UserConfigDir = "tmp"

	// an example of a valid X509 self-signed certificate for demo purpose ONLY.
	// Users should replace `exampleX509Certificate` with their own trusted
	// certificate and add to the trust store, following the
	// Notary certificate requirements:
	// https://github.com/notaryproject/notaryproject/blob/v1.0.0-rc.1/specs/signature-specification.md#certificate-requirements
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
	err := os.MkdirAll("tmp/truststore/x509/ca/valid-trust-store", 0700)
	if err != nil {
		panic(err) // Handle error
	}
	err = os.WriteFile("tmp/truststore/x509/ca/valid-trust-store/NotationExample.pem", []byte(exampleX509Certificate), 0600)
	if err != nil {
		panic(err) // Handle error
	}
}
