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
	"strings"

	"github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
)

// exampleBlobPolicyDocument is an example of a valid blob trust policy document.
// blob trust policy document should follow this spec:
// https://github.com/notaryproject/specifications/blob/main/specs/trust-store-trust-policy.md#blob-trust-policy
var exampleBlobPolicyDocument = trustpolicy.BlobDocument{
	Version: "1.0",
	TrustPolicies: []trustpolicy.BlobTrustPolicy{
		{
			Name:                  "test-statement-name",
			SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: trustpolicy.LevelStrict.Name, Override: map[trustpolicy.ValidationType]trustpolicy.ValidationAction{trustpolicy.TypeRevocation: trustpolicy.ActionSkip}},
			TrustStores:           []string{"ca:valid-trust-store"},
			TrustedIdentities:     []string{"*"},
		},
	},
}

// ExampleVerifyBlob demonstrates how to use [notation.VerifyBlob] to verify a
// signature of an arbitrary blob.
func Example_verifyBlob() {
	// Both COSE ("application/cose") and JWS ("application/jose+json")
	// signature mediaTypes are supported.
	exampleSignatureMediaType := jws.MediaTypeEnvelope

	// exampleSignatureEnvelope is a valid signature envelope.
	exampleSignatureEnvelope := getSignatureEnvelope()

	// createTrustStoreForBlobVerify creates a trust store directory for demo purpose.
	// Users could use the default trust store from Notary Project and add trusted
	// certificates into it following the trust store spec:
	// https://github.com/notaryproject/specifications/tree/9c81dc773508dedc5a81c02c8d805de04f65050b/specs/trust-store-trust-policy.md#trust-store
	if err := createTrustStoreForBlobVerify(); err != nil {
		panic(err) // Handle error
	}

	// exampleVerifier implements [notation.Verify] and [notation.VerifyBlob].
	exampleVerifier, err := verifier.NewVerifier(nil, &exampleBlobPolicyDocument, truststore.NewX509TrustStore(dir.ConfigFS()), nil)
	if err != nil {
		panic(err) // Handle error
	}

	// exampleReader reads the data that needs to be verified.
	// This data can be in a file or in memory.
	exampleReader := strings.NewReader("example blob")

	// exampleVerifyOptions is an example of [notation.VerifyBlobOptions]
	exampleVerifyOptions := notation.VerifyBlobOptions{
		BlobVerifierVerifyOptions: notation.BlobVerifierVerifyOptions{
			SignatureMediaType: exampleSignatureMediaType,
			TrustPolicyName:    "test-statement-name",
		},
	}

	// upon successful verification, the signature verification outcome is
	// returned.
	_, outcome, err := notation.VerifyBlob(context.Background(), exampleVerifier, exampleReader, []byte(exampleSignatureEnvelope), exampleVerifyOptions)
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
	// payload Content: {"targetArtifact":{"digest":"sha384:b8ab24dafba5cf7e4c89c562f811cf10493d4203da982d3b1345f366ca863d9c2ed323dbd0fb7ff83a80302ceffa5a61","mediaType":"video/mp4","size":12}}
}

func createTrustStoreForBlobVerify() error {
	// changing the path of the trust store for demo purpose.
	// Users could keep the default value, i.e. os.UserConfigDir.
	dir.UserConfigDir = "tmp"

	// an example of a valid X509 self-signed certificate for demo purpose ONLY.
	// (This self-signed cert is paired with the private key used to
	// generate the `exampleSignatureEnvelopePem` above.)
	// Users should replace `exampleX509Certificate` with their own trusted
	// certificate and add to the trust store, following the
	// Notary Project certificate requirements:
	// https://github.com/notaryproject/specifications/tree/9c81dc773508dedc5a81c02c8d805de04f65050b/specs/signature-specification.md#certificate-requirements
	exampleX509Certificate := `-----BEGIN CERTIFICATE-----
MIIEbDCCAtSgAwIBAgIBUzANBgkqhkiG9w0BAQsFADBkMQswCQYDVQQGEwJVUzEL
MAkGA1UECBMCV0ExEDAOBgNVBAcTB1NlYXR0bGUxDzANBgNVBAoTBk5vdGFyeTEl
MCMGA1UEAxMcTm90YXRpb24gRXhhbXBsZSBzZWxmLXNpZ25lZDAgFw0yNDA0MDQy
MTIwMjBaGA8yMTI0MDQwNDIxMjAyMFowZDELMAkGA1UEBhMCVVMxCzAJBgNVBAgT
AldBMRAwDgYDVQQHEwdTZWF0dGxlMQ8wDQYDVQQKEwZOb3RhcnkxJTAjBgNVBAMT
HE5vdGF0aW9uIEV4YW1wbGUgc2VsZi1zaWduZWQwggGiMA0GCSqGSIb3DQEBAQUA
A4IBjwAwggGKAoIBgQDGIiN4yCjSVqFELZwxK/BMb8BokP587L8oPrZ1g8H7LudB
moLNDT7vF9xccbCfU3yNuOd0WaOgnENiCs81VHidyJsj1Oz3u+0Zn3ng7V+uZr6m
AIO74efA9ClMiY4i4HIt8IAZF57AL2mzDnCITgSWxikf030Il85MI42STvA+qYuz
ZEOp3XvKo8bDgQFvbtgK0HYYMfrka7VDmIWVo0rBMGm5btI8HOYQ0r9aqsrCxLAv
1AQeOQm+wbRcp4R5PIUJr+REGn7JCbOyXg/7qqHXKKmvV5yrGaraw8gZ5pqP/RHK
XUJIfvD0Vf2epJmsvC+6vXkSWtz+cA8J4GQx4J4SXL57hoYkC5qv39SOLzlWls3I
6fgeO+SZ0sceMd8NKlom/L5eOJBfB3bTQB83hq/3bRtjT7/qCMsL3VcndKkS+vGF
JPw5uTH+pmBgHrLr6tRoRRjwRFuZ0dO05AbdjCaxgVDtFI3wNbaXn/1VlRGySQIS
UNWxCrUsSzndeqwmjqsCAwEAAaMnMCUwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQM
MAoGCCsGAQUFBwMDMA0GCSqGSIb3DQEBCwUAA4IBgQBdi0SaJAaeKBB0I+Fjcbmc
4zRvHE4GDSMSDnAK97nrZCZ9iwKuY4x6mv9lwQe2P3VXROoL9JmONNf0yaObOwQj
ILGnbe2rzYtUardz2gzh+6KNzJHspRvk1f06mp4496XQ3STMRSr8kno1svKQMy0Y
FRsGMKs4fWHavIAqNXg9ymrZvvXiatN2UiVtAA/jBFScZAWskeb2WHNzORi7H5Z1
mp5+IlNYQpzdIu/dvLVxzhh2UvkRdsQqsMgt/MOU84RncwUNZM4yI5EGPoaSJdsj
AGNd+UV6ur7QmVI2Q9EZNRlaDJtaoZmKns5j1SlmDXWKbdRmw42ORDudODj/pHA9
+u+ca9t3uLsbqO9yPm8m+6fyxffWS11QAH6O7EjydJWcEe5tYkPpL6kcaEyQKESm
5CDlsk+W3ElpaUu6tsnGKODvgdAN3m0noC+qxzCMqoCM4+M5V6OptR98MDl2FK0B
5+WF6YHBxf/uqDvFktUczjrIWuyfECywp05bpGAErGE=
-----END CERTIFICATE-----`

	// Adding the certificate into the trust store.
	if err := os.MkdirAll("tmp/truststore/x509/ca/valid-trust-store", 0700); err != nil {
		return err
	}
	return os.WriteFile("tmp/truststore/x509/ca/valid-trust-store/NotationBlobExample.pem", []byte(exampleX509Certificate), 0600)
}

func getSignatureEnvelope() string {
	return `{"payload":"eyJ0YXJnZXRBcnRpZmFjdCI6eyJkaWdlc3QiOiJzaGEzODQ6YjhhYjI0ZGFmYmE1Y2Y3ZTRjODljNTYyZjgxMWNmMTA0OTNkNDIwM2RhOTgyZDNiMTM0NWYzNjZjYTg2M2Q5YzJlZDMyM2RiZDBmYjdmZjgzYTgwMzAyY2VmZmE1YTYxIiwibWVkaWFUeXBlIjoidmlkZW8vbXA0Iiwic2l6ZSI6MTJ9fQ","protected":"eyJhbGciOiJQUzM4NCIsImNyaXQiOlsiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1NjaGVtZSJdLCJjdHkiOiJhcHBsaWNhdGlvbi92bmQuY25jZi5ub3RhcnkucGF5bG9hZC52MStqc29uIiwiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1NjaGVtZSI6Im5vdGFyeS54NTA5IiwiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1RpbWUiOiIyMDI0LTA0LTA0VDE0OjIwOjIxLTA3OjAwIn0","header":{"x5c":["MIIEbDCCAtSgAwIBAgIBUzANBgkqhkiG9w0BAQsFADBkMQswCQYDVQQGEwJVUzELMAkGA1UECBMCV0ExEDAOBgNVBAcTB1NlYXR0bGUxDzANBgNVBAoTBk5vdGFyeTElMCMGA1UEAxMcTm90YXRpb24gRXhhbXBsZSBzZWxmLXNpZ25lZDAgFw0yNDA0MDQyMTIwMjBaGA8yMTI0MDQwNDIxMjAyMFowZDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAldBMRAwDgYDVQQHEwdTZWF0dGxlMQ8wDQYDVQQKEwZOb3RhcnkxJTAjBgNVBAMTHE5vdGF0aW9uIEV4YW1wbGUgc2VsZi1zaWduZWQwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDGIiN4yCjSVqFELZwxK/BMb8BokP587L8oPrZ1g8H7LudBmoLNDT7vF9xccbCfU3yNuOd0WaOgnENiCs81VHidyJsj1Oz3u+0Zn3ng7V+uZr6mAIO74efA9ClMiY4i4HIt8IAZF57AL2mzDnCITgSWxikf030Il85MI42STvA+qYuzZEOp3XvKo8bDgQFvbtgK0HYYMfrka7VDmIWVo0rBMGm5btI8HOYQ0r9aqsrCxLAv1AQeOQm+wbRcp4R5PIUJr+REGn7JCbOyXg/7qqHXKKmvV5yrGaraw8gZ5pqP/RHKXUJIfvD0Vf2epJmsvC+6vXkSWtz+cA8J4GQx4J4SXL57hoYkC5qv39SOLzlWls3I6fgeO+SZ0sceMd8NKlom/L5eOJBfB3bTQB83hq/3bRtjT7/qCMsL3VcndKkS+vGFJPw5uTH+pmBgHrLr6tRoRRjwRFuZ0dO05AbdjCaxgVDtFI3wNbaXn/1VlRGySQISUNWxCrUsSzndeqwmjqsCAwEAAaMnMCUwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA0GCSqGSIb3DQEBCwUAA4IBgQBdi0SaJAaeKBB0I+Fjcbmc4zRvHE4GDSMSDnAK97nrZCZ9iwKuY4x6mv9lwQe2P3VXROoL9JmONNf0yaObOwQjILGnbe2rzYtUardz2gzh+6KNzJHspRvk1f06mp4496XQ3STMRSr8kno1svKQMy0YFRsGMKs4fWHavIAqNXg9ymrZvvXiatN2UiVtAA/jBFScZAWskeb2WHNzORi7H5Z1mp5+IlNYQpzdIu/dvLVxzhh2UvkRdsQqsMgt/MOU84RncwUNZM4yI5EGPoaSJdsjAGNd+UV6ur7QmVI2Q9EZNRlaDJtaoZmKns5j1SlmDXWKbdRmw42ORDudODj/pHA9+u+ca9t3uLsbqO9yPm8m+6fyxffWS11QAH6O7EjydJWcEe5tYkPpL6kcaEyQKESm5CDlsk+W3ElpaUu6tsnGKODvgdAN3m0noC+qxzCMqoCM4+M5V6OptR98MDl2FK0B5+WF6YHBxf/uqDvFktUczjrIWuyfECywp05bpGAErGE="],"io.cncf.notary.signingAgent":"example signing agent"},"signature":"liOjdgQ9BKuQTZGXRh3o6P8AMUIq_MKQReEcqA5h8M4RYs3DV_wXfaLCr2x_NRcwjTZsoO1_J77hmzkkk4L0IuFP8Qw0KKtmc83G0yFi4yYV5fwzrIbnhC2GRLuqLPnK-C4qYmv52ld3ebvo7XWwRHu30-VXePmTRFp6iG-eSAgkNgwhxSZ0ZmTFLG3ceNiX2bxpLHlXdPwA3aFKbd6nKrzo4CZ1ZyLNmAIaoA5-kmc0Hyt45trpxaaiWusI_pcTLw71YCqEAs32tEq3q6hRAgAZZN-Qvm9GyNp9EuaPiKjMbJFqtjome5ITxyNd-5t09dDCUgSe3t-iqv2Blm4E080AP1TYwUKLYklGniUP1dAtOau5G2juZLpl7tr4LQ99mycflnAmV7e79eEWXffvy5EAl77dW4_vM7lEemm08m2wddGuDOWXYb1j1r2_a5Xb92umHq6ZMhAp200A0pUkm9640x8z5jdudi_7KeezdqUK7ZMmSxHohiylyKD_20Cy"}`
}
