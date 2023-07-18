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
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/notaryproject/notation-core-go/signature/cose"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// examplePolicyDocument is an example of a valid trust policy document.
// trust policy document should follow this spec:
// https://github.com/notaryproject/notaryproject/blob/v1.0.0-rc.1/specs/trust-store-trust-policy.md#trust-policy
var examplePolicyDocument = trustpolicy.Document{
	Version: "1.0",
	TrustPolicies: []trustpolicy.TrustPolicy{
		{
			Name:                  "test-statement-name",
			RegistryScopes:        []string{"example/software"},
			SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: trustpolicy.LevelStrict.Name, Override: map[trustpolicy.ValidationType]trustpolicy.ValidationAction{trustpolicy.TypeRevocation: trustpolicy.ActionSkip}},
			TrustStores:           []string{"ca:valid-trust-store"},
			TrustedIdentities:     []string{"*"},
		},
	},
}

// ExampleLocalVerify demonstrates how to use verifier.Verify to verify a
// signature of the target artifact at local (without using a
// registry.Repository).
func Example_localVerify() {
	// exampleArtifactReference is an example of the target artifact reference
	exampleArtifactReference := "example/software@sha256:c0d488a800e4127c334ad20d61d7bc21b4097540327217dfab52262adc02380c"

	// Both COSE ("application/cose") and JWS ("application/jose+json")
	// signature mediaTypes are supported.
	exampleSignatureMediaType := cose.MediaTypeEnvelope

	// exampleTargetDescriptor is an example of the target manifest descriptor.
	exampleTargetDescriptor := ocispec.Descriptor{
		MediaType: "application/vnd.docker.distribution.manifest.v2+json",
		Digest:    "sha256:c0d488a800e4127c334ad20d61d7bc21b4097540327217dfab52262adc02380c",
		Size:      528,
	}

	// exampleSignatureEnvelope is a valid signature envelope.
	exampleSignatureEnvelope := generateExampleSignatureEnvelope()

	// exampleVerifyOptions is an example of notation.VerifierVerifyOptions
	exampleVerifyOptions := notation.VerifierVerifyOptions{
		ArtifactReference:  exampleArtifactReference,
		SignatureMediaType: exampleSignatureMediaType,
	}

	// createTrustStore creates a trust store directory for demo purpose.
	// Users could use the default trust store from Notary and add trusted
	// certificates into it following the trust store spec:
	// https://github.com/notaryproject/notaryproject/blob/v1.0.0-rc.1/specs/trust-store-trust-policy.md#trust-store
	if err := createTrustStore(); err != nil {
		panic(err) // Handle error
	}

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

func generateExampleSignatureEnvelope() []byte {
	// exampleSignatureEnvelopePem is a valid signature envelope in COSE format
	// wrapped by a PEM block.
	// The signature envelope is generated in a previous Sign process.
	// Users should replace it with their own signature envelope.
	// Regarding how to generate such signature envelopes, users could refer to
	// `example_localSign_test.go`.
	exampleSignatureEnvelopePem := `-----BEGIN EXAMPLE SIGNATURE ENVELOPE-----
0oRYnqUBOCQCgXgcaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1NjaGVtZQN4K2FwcGxp
Y2F0aW9uL3ZuZC5jbmNmLm5vdGFyeS5wYXlsb2FkLnYxK2pzb254GmlvLmNuY2Yu
bm90YXJ5LnNpZ25pbmdUaW1lwRpju22GeBxpby5jbmNmLm5vdGFyeS5zaWduaW5n
U2NoZW1la25vdGFyeS54NTA5ohghgVkDRDCCA0AwggIooAMCAQICAVEwDQYJKoZI
hvcNAQELBQAwTjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAldBMRAwDgYDVQQHEwdT
ZWF0dGxlMQ8wDQYDVQQKEwZOb3RhcnkxDzANBgNVBAMTBmFscGluZTAgFw0wMDA4
MjkxMzUwMDBaGA8yMTIzMDgyOTEzNTAwMFowTjELMAkGA1UEBhMCVVMxCzAJBgNV
BAgTAldBMRAwDgYDVQQHEwdTZWF0dGxlMQ8wDQYDVQQKEwZOb3RhcnkxDzANBgNV
BAMTBmFscGluZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKHIN6hL
MjQwy3wfDhw+HYYvjNTTytQLMuTV/OHPoL2nGbqDy08JqTn5upz7exjzwfRu0usc
YRTW0cU2H2FIyvpGgo9/F4wUX+ZRnsG0iSlZMUPNv2sVO9HHkltyaWs62oHjfSVE
2fyX4uDH54qSE8HJjKIoo/Hhqx7JI8lcmWyXdFjDCkQ1lYSz1IjzFVrf+He2LWSL
c2nGkCrV5l4LEwk1qSKJbN4H7TWI60KDLFHpVHQ/LzgFjfSdvP0sgvrkofytSn8l
JW6rn5+HYvAxAcZ7T+cJ12GyS9Y7Y7FIBMQFY0MU9cyOfV9+pt7d2CqgkIdXLndN
i+aJzm2Os4+ezekCAwEAAaMnMCUwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoG
CCsGAQUFBwMDMA0GCSqGSIb3DQEBCwUAA4IBAQAvAIwS8uxLEaYuqILgnRUm+p0R
o7xdezfm+pg297AEZwfE9acb8009usmvgMlkfo46HRMGzCEvtd5Vfvak9i8KpWzl
DWOdfT2thkUWO9iY3qMFiN4ipCmjM32VAe5UUxl3RLmQKS20zv9yVXEfX37tNDdV
GgD/WBhJUreCQyWAPTPnf0LaPh4iLBNCo/o3Z8CGKLzzzpa8iji3xW/69RhKu5+t
8RWc/N4sljWmXbCeTd2B8XTqZGwWwmpThAQyU40CqngGAS6ADTVNDgbJZqhwkgUx
J4W6iRzekCshdPUnDpeS8DNULE5dFGObIhiwH4/40n/Th/VS0zxzkvPzdCmueBtp
by5jbmNmLm5vdGFyeS5zaWduaW5nQWdlbnRuTm90YXRpb24vMS4wLjBYtXsidGFy
Z2V0QXJ0aWZhY3QiOnsibWVkaWFUeXBlIjoiYXBwbGljYXRpb24vdm5kLmRvY2tl
ci5kaXN0cmlidXRpb24ubWFuaWZlc3QudjIranNvbiIsImRpZ2VzdCI6InNoYTI1
NjpjMGQ0ODhhODAwZTQxMjdjMzM0YWQyMGQ2MWQ3YmMyMWI0MDk3NTQwMzI3MjE3
ZGZhYjUyMjYyYWRjMDIzODBjIiwic2l6ZSI6NTI4fX1ZAQBUIYPA45B/iFylmloW
s/NpTVsheuedJb6nnXK0XR46BYs4AeCXVVYSRDK2Bq+tA9C7BXHoeCMcqnAHa8qs
ZR/fcMa9FrEPI6Pl8QVE/6QRMkT+Drn+9CSFxzHk6CU9S1vRsUVYNcibyejnuVEE
RPYaORrnfTc5wIs4XxeqprmrLimMMNn+u82Uadtc57tbHbY8Vh4XEKP++hBJJNvQ
E60X5aWKIS2RnOEc4n9T7LdN0bOL1OoM1lW4iTFMhzfcy/VmF8PrOStFS9LllX3J
69V0WwHbmD33cjtVBDCF44UXRWgLQGbE6yaaVmdxEUBGKqSUeHf8Gp7WoZ/YaFmz
xQr/
-----END EXAMPLE SIGNATURE ENVELOPE-----`

	block, _ := pem.Decode([]byte(exampleSignatureEnvelopePem))
	if block == nil {
		panic(errors.New("invalid signature envelope pem block"))
	}

	// block.Bytes contains the binary of the signature envelope.
	return block.Bytes
}

func createTrustStore() error {
	// changing the path of the trust store for demo purpose.
	// Users could keep the default value, i.e. os.UserConfigDir.
	dir.UserConfigDir = "tmp"

	// an example of a valid X509 self-signed certificate for demo purpose ONLY.
	// (This self-signed cert is paired with the private key used to
	// generate the `exampleSignatureEnvelopePem` above.)
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
		return err
	}
	return os.WriteFile("tmp/truststore/x509/ca/valid-trust-store/NotationLocalExample.pem", []byte(exampleX509Certificate), 0600)
}
