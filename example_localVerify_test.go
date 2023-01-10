package notation_test

import (
	"context"
	"fmt"
	"os"

	_ "github.com/notaryproject/notation-core-go/signature/cose"
	_ "github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

var (
	// examplePolicyDocument is an example of a valid trust policy document.
	// trust policy document should follow this spec:
	// https://github.com/notaryproject/notaryproject/blob/v1.0.0-rc.1/specs/trust-store-trust-policy.md#trust-policy
	examplePolicyDocument = trustpolicy.Document{
		Version: "1.0",
		TrustPolicies: []trustpolicy.TrustPolicy{
			{
				Name:                  "test-statement-name",
				RegistryScopes:        []string{"example/software"},
				SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: "strict"},
				TrustStores:           []string{"ca:valid-trust-store"},
				TrustedIdentities:     []string{"*"},
			},
		},
	}
)

// ExampleLocalVerify demonstrates how to use verifier.Verify to verify a
// signature of the target artifact at local (without using a
// registry.Repository).
func Example_localVerify() {
	// exampleArtifactReference is an example of the target artifact reference
	exampleArtifactReference := "example/software@sha256:c0d488a800e4127c334ad20d61d7bc21b4097540327217dfab52262adc02380c"

	// Both COSE ("application/cose") and JWS ("application/jose+json")
	// signature mediaTypes are supported.
	exampleSignatureMediaType := "application/cose"

	// exampleTargetDescriptor is an example of the target OCI artifact manifest
	// descriptor.
	exampleTargetDescriptor := ocispec.Descriptor{
		MediaType: "application/vnd.docker.distribution.manifest.v2+json",
		Digest:    digest.Digest("sha256:c0d488a800e4127c334ad20d61d7bc21b4097540327217dfab52262adc02380c"),
		Size:      int64(528),
	}

	// exampleSignatureEnvelope is a valid signature envelope in COSE format.
	// it is generated in a previous Sign process.
	// Users should replace it with their own signature envelope.
	exampleSignatureEnvelope := []byte{210, 132, 88, 158, 165, 1, 56, 36, 2, 129, 120, 28, 105, 111, 46, 99, 110, 99, 102, 46, 110, 111, 116, 97, 114, 121, 46, 115, 105, 103, 110, 105, 110, 103, 83, 99, 104, 101, 109, 101, 3, 120, 43, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 118, 110, 100, 46, 99, 110, 99, 102, 46, 110, 111, 116, 97, 114, 121, 46, 112, 97, 121, 108, 111, 97, 100, 46, 118, 49, 43, 106, 115, 111, 110, 120, 26, 105, 111, 46, 99, 110, 99, 102, 46, 110, 111, 116, 97, 114, 121, 46, 115, 105, 103, 110, 105, 110, 103, 84, 105, 109, 101, 193, 26, 99, 187, 109, 134, 120, 28, 105, 111, 46, 99, 110, 99, 102, 46, 110, 111, 116, 97, 114, 121, 46, 115, 105, 103, 110, 105, 110, 103, 83, 99, 104, 101, 109, 101, 107, 110, 111, 116, 97, 114, 121, 46, 120, 53, 48, 57, 162, 24, 33, 129, 89, 3, 68, 48, 130, 3, 64, 48, 130, 2, 40, 160, 3, 2, 1, 2, 2, 1, 81, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 48, 78, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 11, 48, 9, 6, 3, 85, 4, 8, 19, 2, 87, 65, 49, 16, 48, 14, 6, 3, 85, 4, 7, 19, 7, 83, 101, 97, 116, 116, 108, 101, 49, 15, 48, 13, 6, 3, 85, 4, 10, 19, 6, 78, 111, 116, 97, 114, 121, 49, 15, 48, 13, 6, 3, 85, 4, 3, 19, 6, 97, 108, 112, 105, 110, 101, 48, 32, 23, 13, 48, 48, 48, 56, 50, 57, 49, 51, 53, 48, 48, 48, 90, 24, 15, 50, 49, 50, 51, 48, 56, 50, 57, 49, 51, 53, 48, 48, 48, 90, 48, 78, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 11, 48, 9, 6, 3, 85, 4, 8, 19, 2, 87, 65, 49, 16, 48, 14, 6, 3, 85, 4, 7, 19, 7, 83, 101, 97, 116, 116, 108, 101, 49, 15, 48, 13, 6, 3, 85, 4, 10, 19, 6, 78, 111, 116, 97, 114, 121, 49, 15, 48, 13, 6, 3, 85, 4, 3, 19, 6, 97, 108, 112, 105, 110, 101, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 161, 200, 55, 168, 75, 50, 52, 48, 203, 124, 31, 14, 28, 62, 29, 134, 47, 140, 212, 211, 202, 212, 11, 50, 228, 213, 252, 225, 207, 160, 189, 167, 25, 186, 131, 203, 79, 9, 169, 57, 249, 186, 156, 251, 123, 24, 243, 193, 244, 110, 210, 235, 28, 97, 20, 214, 209, 197, 54, 31, 97, 72, 202, 250, 70, 130, 143, 127, 23, 140, 20, 95, 230, 81, 158, 193, 180, 137, 41, 89, 49, 67, 205, 191, 107, 21, 59, 209, 199, 146, 91, 114, 105, 107, 58, 218, 129, 227, 125, 37, 68, 217, 252, 151, 226, 224, 199, 231, 138, 146, 19, 193, 201, 140, 162, 40, 163, 241, 225, 171, 30, 201, 35, 201, 92, 153, 108, 151, 116, 88, 195, 10, 68, 53, 149, 132, 179, 212, 136, 243, 21, 90, 223, 248, 119, 182, 45, 100, 139, 115, 105, 198, 144, 42, 213, 230, 94, 11, 19, 9, 53, 169, 34, 137, 108, 222, 7, 237, 53, 136, 235, 66, 131, 44, 81, 233, 84, 116, 63, 47, 56, 5, 141, 244, 157, 188, 253, 44, 130, 250, 228, 161, 252, 173, 74, 127, 37, 37, 110, 171, 159, 159, 135, 98, 240, 49, 1, 198, 123, 79, 231, 9, 215, 97, 178, 75, 214, 59, 99, 177, 72, 4, 196, 5, 99, 67, 20, 245, 204, 142, 125, 95, 126, 166, 222, 221, 216, 42, 160, 144, 135, 87, 46, 119, 77, 139, 230, 137, 206, 109, 142, 179, 143, 158, 205, 233, 2, 3, 1, 0, 1, 163, 39, 48, 37, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 7, 128, 48, 19, 6, 3, 85, 29, 37, 4, 12, 48, 10, 6, 8, 43, 6, 1, 5, 5, 7, 3, 3, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 3, 130, 1, 1, 0, 47, 0, 140, 18, 242, 236, 75, 17, 166, 46, 168, 130, 224, 157, 21, 38, 250, 157, 17, 163, 188, 93, 123, 55, 230, 250, 152, 54, 247, 176, 4, 103, 7, 196, 245, 167, 27, 243, 77, 61, 186, 201, 175, 128, 201, 100, 126, 142, 58, 29, 19, 6, 204, 33, 47, 181, 222, 85, 126, 246, 164, 246, 47, 10, 165, 108, 229, 13, 99, 157, 125, 61, 173, 134, 69, 22, 59, 216, 152, 222, 163, 5, 136, 222, 34, 164, 41, 163, 51, 125, 149, 1, 238, 84, 83, 25, 119, 68, 185, 144, 41, 45, 180, 206, 255, 114, 85, 113, 31, 95, 126, 237, 52, 55, 85, 26, 0, 255, 88, 24, 73, 82, 183, 130, 67, 37, 128, 61, 51, 231, 127, 66, 218, 62, 30, 34, 44, 19, 66, 163, 250, 55, 103, 192, 134, 40, 188, 243, 206, 150, 188, 138, 56, 183, 197, 111, 250, 245, 24, 74, 187, 159, 173, 241, 21, 156, 252, 222, 44, 150, 53, 166, 93, 176, 158, 77, 221, 129, 241, 116, 234, 100, 108, 22, 194, 106, 83, 132, 4, 50, 83, 141, 2, 170, 120, 6, 1, 46, 128, 13, 53, 77, 14, 6, 201, 102, 168, 112, 146, 5, 49, 39, 133, 186, 137, 28, 222, 144, 43, 33, 116, 245, 39, 14, 151, 146, 240, 51, 84, 44, 78, 93, 20, 99, 155, 34, 24, 176, 31, 143, 248, 210, 127, 211, 135, 245, 82, 211, 60, 115, 146, 243, 243, 116, 41, 174, 120, 27, 105, 111, 46, 99, 110, 99, 102, 46, 110, 111, 116, 97, 114, 121, 46, 115, 105, 103, 110, 105, 110, 103, 65, 103, 101, 110, 116, 110, 78, 111, 116, 97, 116, 105, 111, 110, 47, 49, 46, 48, 46, 48, 88, 181, 123, 34, 116, 97, 114, 103, 101, 116, 65, 114, 116, 105, 102, 97, 99, 116, 34, 58, 123, 34, 109, 101, 100, 105, 97, 84, 121, 112, 101, 34, 58, 34, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 118, 110, 100, 46, 100, 111, 99, 107, 101, 114, 46, 100, 105, 115, 116, 114, 105, 98, 117, 116, 105, 111, 110, 46, 109, 97, 110, 105, 102, 101, 115, 116, 46, 118, 50, 43, 106, 115, 111, 110, 34, 44, 34, 100, 105, 103, 101, 115, 116, 34, 58, 34, 115, 104, 97, 50, 53, 54, 58, 99, 48, 100, 52, 56, 56, 97, 56, 48, 48, 101, 52, 49, 50, 55, 99, 51, 51, 52, 97, 100, 50, 48, 100, 54, 49, 100, 55, 98, 99, 50, 49, 98, 52, 48, 57, 55, 53, 52, 48, 51, 50, 55, 50, 49, 55, 100, 102, 97, 98, 53, 50, 50, 54, 50, 97, 100, 99, 48, 50, 51, 56, 48, 99, 34, 44, 34, 115, 105, 122, 101, 34, 58, 53, 50, 56, 125, 125, 89, 1, 0, 84, 33, 131, 192, 227, 144, 127, 136, 92, 165, 154, 90, 22, 179, 243, 105, 77, 91, 33, 122, 231, 157, 37, 190, 167, 157, 114, 180, 93, 30, 58, 5, 139, 56, 1, 224, 151, 85, 86, 18, 68, 50, 182, 6, 175, 173, 3, 208, 187, 5, 113, 232, 120, 35, 28, 170, 112, 7, 107, 202, 172, 101, 31, 223, 112, 198, 189, 22, 177, 15, 35, 163, 229, 241, 5, 68, 255, 164, 17, 50, 68, 254, 14, 185, 254, 244, 36, 133, 199, 49, 228, 232, 37, 61, 75, 91, 209, 177, 69, 88, 53, 200, 155, 201, 232, 231, 185, 81, 4, 68, 246, 26, 57, 26, 231, 125, 55, 57, 192, 139, 56, 95, 23, 170, 166, 185, 171, 46, 41, 140, 48, 217, 254, 187, 205, 148, 105, 219, 92, 231, 187, 91, 29, 182, 60, 86, 30, 23, 16, 163, 254, 250, 16, 73, 36, 219, 208, 19, 173, 23, 229, 165, 138, 33, 45, 145, 156, 225, 28, 226, 127, 83, 236, 183, 77, 209, 179, 139, 212, 234, 12, 214, 85, 184, 137, 49, 76, 135, 55, 220, 203, 245, 102, 23, 195, 235, 57, 43, 69, 75, 210, 229, 149, 125, 201, 235, 213, 116, 91, 1, 219, 152, 61, 247, 114, 59, 85, 4, 48, 133, 227, 133, 23, 69, 104, 11, 64, 102, 196, 235, 38, 154, 86, 103, 113, 17, 64, 70, 42, 164, 148, 120, 119, 252, 26, 158, 214, 161, 159, 216, 104, 89, 179, 197, 10, 255}

	// exampleVerifyOptions is an example of notation.VerifyOptions
	exampleVerifyOptions := notation.VerifyOptions{
		ArtifactReference:  exampleArtifactReference,
		SignatureMediaType: exampleSignatureMediaType,
	}

	// createTrustStore creates a trust store directory for demo purpose.
	// Users could use the default trust store from Notary and add trusted
	// certificates into it following the trust store spec:
	// https://github.com/notaryproject/notaryproject/blob/v1.0.0-rc.1/specs/trust-store-trust-policy.md#trust-store
	createTrustStore()

	// exampleVerifier is an example of notation.Verifier given
	// trust policy document and X509 trust store.
	exampleVerifier, err := verifier.New(&examplePolicyDocument, truststore.NewX509TrustStore(dir.ConfigFS()), nil)
	if err != nil {
		panic(err) // Handle error
	}

	// local verify core process
	// upon successful verification, the signature verification outcome is
	// returned.
	outcome, err := exampleVerifier.Verify(context.Background(), exampleTargetDescriptor, exampleSignatureEnvelope, exampleVerifyOptions)
	if err != nil {
		panic(err) // Handle error
	}

	fmt.Println("Successfully verified")

	// a peek of the payload inside the signature envelope
	fmt.Println("payload ContentType:", outcome.EnvelopeContent.Payload.ContentType)

	// Note, upon successful verification, payload.TargetArtifact from the
	// signature envelope matches exactly with our exampleTargetDescriptor.
	// (This check has been done for the user inside verifier.Verify.)
	fmt.Println("payload Content:", string(outcome.EnvelopeContent.Payload.Content))

	// Output:
	// Successfully verified
	// payload ContentType: application/vnd.cncf.notary.payload.v1+json
	// payload Content: {"targetArtifact":{"mediaType":"application/vnd.docker.distribution.manifest.v2+json","digest":"sha256:c0d488a800e4127c334ad20d61d7bc21b4097540327217dfab52262adc02380c","size":528}}
}

func createTrustStore() {
	// changing the path of the trust store for demo purpose.
	// Users could keep the default value, i.e. os.UserConfigDir.
	dir.UserConfigDir = "tmp"

	// an example of a valid X509 self-signed certificate for demo purpose ONLY.
	// (This self-signed cert is paired with the private key used to
	// generate the `exampleSignatureEnvelope` above.)
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
	if err := os.MkdirAll("tmp/truststore/x509/ca/valid-trust-store", 0700); err != nil {
		panic(err) // Handle error
	}
	if err := os.WriteFile("tmp/truststore/x509/ca/valid-trust-store/NotationLocalExample.pem", []byte(exampleX509Certificate), 0600); err != nil {
		panic(err) // Handle error
	}
}
