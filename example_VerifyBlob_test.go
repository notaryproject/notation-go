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

// examplePolicyDocument is an example of a valid trust policy document.
// trust policy document should follow this spec:
// https://github.com/notaryproject/notaryproject/blob/v1.0.0-rc.1/specs/trust-store-trust-policy.md#trust-policy
var exampleBlobPolicyDocument = trustpolicy.BlobDocument{
	Version: "1.0",
	BlobTrustPolicies: []trustpolicy.BlobTrustPolicy{
		{
			Name:                  "test-statement-name",
			SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: trustpolicy.LevelStrict.Name, Override: map[trustpolicy.ValidationType]trustpolicy.ValidationAction{trustpolicy.TypeRevocation: trustpolicy.ActionSkip}},
			TrustStores:           []string{"ca:valid-trust-store"},
			TrustedIdentities:     []string{"*"},
		},
	},
}

// ExampleLocalVerify demonstrates how to use verifier.Verify to verify a
// signature of the target artifact at local (without using a
// registry.Repository).
func Example_BlobVerify() {
	// Both COSE ("application/cose") and JWS ("application/jose+json")
	// signature mediaTypes are supported.
	exampleSignatureMediaType := jws.MediaTypeEnvelope

	// exampleSignatureEnvelope is a valid signature envelope.
	exampleSignatureEnvelope := getSignatureEnvelope()

	// createTrustStoreForBlobVerify creates a trust store directory for demo purpose.
	// Users could use the default trust store from Notary and add trusted
	// certificates into it following the trust store spec:
	// https://github.com/notaryproject/notaryproject/blob/v1.0.0/specs/trust-store-trust-policy.md#trust-store
	if err := createTrustStoreForBlobVerify(); err != nil {
		panic(err) // Handle error
	}

	// exampleVerifier implements notation.Verify and notation.VerifyBlob.
	exampleVerifier, err := verifier.NewVerifier(nil, &exampleBlobPolicyDocument, truststore.NewX509TrustStore(dir.ConfigFS()), nil)
	if err != nil {
		panic(err) // Handle error
	}

	// exampleReader reads the data that needs to be verified. This data can be in a file or in memory.
	exampleReader := strings.NewReader("example blob")

	// exampleVerifyOptions is an example of notation.VerifierVerifyOptions
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
	// Notary certificate requirements:
	// https://github.com/notaryproject/notaryproject/blob/v1.0.0/specs/signature-specification.md#certificate-requirements
	exampleX509Certificate := `-----BEGIN CERTIFICATE-----
MIIEajCCAtKgAwIBAgIBUzANBgkqhkiG9w0BAQsFADBkMQswCQYDVQQGEwJVUzEL
MAkGA1UECBMCV0ExEDAOBgNVBAcTB1NlYXR0bGUxDzANBgNVBAoTBk5vdGFyeTEl
MCMGA1UEAxMcTm90YXRpb24gRXhhbXBsZSBzZWxmLXNpZ25lZDAeFw0yNDA0MDIw
MjU2MzJaFw0yNDA0MDMwMjU2MzJaMGQxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJX
QTEQMA4GA1UEBxMHU2VhdHRsZTEPMA0GA1UEChMGTm90YXJ5MSUwIwYDVQQDExxO
b3RhdGlvbiBFeGFtcGxlIHNlbGYtc2lnbmVkMIIBojANBgkqhkiG9w0BAQEFAAOC
AY8AMIIBigKCAYEApZbB7U2x+XnucIVUoFEjUkNnjkZ0jpNfndHF49rTpqJTstsP
slW/d3qRlrTvsT61iaerLfFoIMkAq2G8KIOY0tCijyr3witWaeyd9sIvGggj770u
wngVpmASUuRZfmltHcTkn7m2gwJATuUc1ugHvxRE2+A7jbd2m7CfjGmwN+THg0Xe
5MggOKKd/2nEvePUsNedMF2Po5hzHG3rNQVxNyzbseIiDUq4qGl7h6zUIuYoSP0k
IPhsAPq9zhPkdXTQw39Ch3iDrVN/D+xOYuTukURFX45SnSTaqiFZEBoDEKIqfAwz
GUIm+yL5eNk6OOCZlmffXVadwdCnhwGMit8TUQQQOPtE3ALSRiXfdKUeBnkDIhcV
3MGLcrPy7kyq3IK7WwHhdfhhxGmJVAaZ/FuseeVT881UVD2Opj1j+MRWSurEiyiM
G/sTLEO53fIpp4eTP78CD6dYTrMC277C6X91WtCxQSnsYThP2miZHwZZY2jYt+hT
DpmWBP3i4ijl+75/AgMBAAGjJzAlMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAK
BggrBgEFBQcDAzANBgkqhkiG9w0BAQsFAAOCAYEARLg5VcXNRdWaEuM01iheXzBL
AtGmZLf+fA4nl8j4FktNfYci1GtqwJqDmfXj74xXGgltnX4uMG+dTPln3c+tHJn3
OJBgvCeB2sZWMoV4wjLZo1XOcIszdxUY7rI3PA/2ZRm75v7Qf0Yvg5DQRUgMMlvo
7Wu07mZoNLVccABndvj6nCntKaRu48YexXFWX+Y3qn8rCidH61Q8rmScdrSnYCwT
0TM23GoszeCtgdShgA0/NqqTefpC90zoKISze3K0zyIfsn9+kw3JHbw+PnqSQ/z8
NqG/FGiv0x4fk0FZ9yOpT+4CoVGgnCub7YEYtUGQL70GbTjPXMto+hnXK3maWzBz
tOQxZrHLSIdOXaLfnRE+vGEDQ29hxQJj/S9H6WbXz6Gx1UpHp8y5RjWiphHV555F
/Ham1A4O1H2mK8l4b7oufB1u3cah1uQZ64xzr0VHVQnzmCm1MwQUkmF+5B/Ce9mC
IqbYJlmoCQWeDVqVSpPJrZgTmcA+djqsvhTi7zbr
-----END CERTIFICATE-----`

	// Adding the certificate into the trust store.
	if err := os.MkdirAll("tmp/truststore/x509/ca/valid-trust-store", 0700); err != nil {
		return err
	}
	return os.WriteFile("tmp/truststore/x509/ca/valid-trust-store/NotationBlobExample.pem", []byte(exampleX509Certificate), 0600)
}

func getSignatureEnvelope() string {
	return `{"payload":"eyJ0YXJnZXRBcnRpZmFjdCI6eyJkaWdlc3QiOiJzaGEzODQ6YjhhYjI0ZGFmYmE1Y2Y3ZTRjODljNTYyZjgxMWNmMTA0OTNkNDIwM2RhOTgyZDNiMTM0NWYzNjZjYTg2M2Q5YzJlZDMyM2RiZDBmYjdmZjgzYTgwMzAyY2VmZmE1YTYxIiwibWVkaWFUeXBlIjoidmlkZW8vbXA0Iiwic2l6ZSI6MTJ9fQ","protected":"eyJhbGciOiJQUzM4NCIsImNyaXQiOlsiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1NjaGVtZSJdLCJjdHkiOiJhcHBsaWNhdGlvbi92bmQuY25jZi5ub3RhcnkucGF5bG9hZC52MStqc29uIiwiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1NjaGVtZSI6Im5vdGFyeS54NTA5IiwiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1RpbWUiOiIyMDI0LTA0LTAxVDE5OjU2OjMzLTA3OjAwIn0","header":{"x5c":["MIIEajCCAtKgAwIBAgIBUzANBgkqhkiG9w0BAQsFADBkMQswCQYDVQQGEwJVUzELMAkGA1UECBMCV0ExEDAOBgNVBAcTB1NlYXR0bGUxDzANBgNVBAoTBk5vdGFyeTElMCMGA1UEAxMcTm90YXRpb24gRXhhbXBsZSBzZWxmLXNpZ25lZDAeFw0yNDA0MDIwMjU2MzJaFw0yNDA0MDMwMjU2MzJaMGQxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJXQTEQMA4GA1UEBxMHU2VhdHRsZTEPMA0GA1UEChMGTm90YXJ5MSUwIwYDVQQDExxOb3RhdGlvbiBFeGFtcGxlIHNlbGYtc2lnbmVkMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEApZbB7U2x+XnucIVUoFEjUkNnjkZ0jpNfndHF49rTpqJTstsPslW/d3qRlrTvsT61iaerLfFoIMkAq2G8KIOY0tCijyr3witWaeyd9sIvGggj770uwngVpmASUuRZfmltHcTkn7m2gwJATuUc1ugHvxRE2+A7jbd2m7CfjGmwN+THg0Xe5MggOKKd/2nEvePUsNedMF2Po5hzHG3rNQVxNyzbseIiDUq4qGl7h6zUIuYoSP0kIPhsAPq9zhPkdXTQw39Ch3iDrVN/D+xOYuTukURFX45SnSTaqiFZEBoDEKIqfAwzGUIm+yL5eNk6OOCZlmffXVadwdCnhwGMit8TUQQQOPtE3ALSRiXfdKUeBnkDIhcV3MGLcrPy7kyq3IK7WwHhdfhhxGmJVAaZ/FuseeVT881UVD2Opj1j+MRWSurEiyiMG/sTLEO53fIpp4eTP78CD6dYTrMC277C6X91WtCxQSnsYThP2miZHwZZY2jYt+hTDpmWBP3i4ijl+75/AgMBAAGjJzAlMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzANBgkqhkiG9w0BAQsFAAOCAYEARLg5VcXNRdWaEuM01iheXzBLAtGmZLf+fA4nl8j4FktNfYci1GtqwJqDmfXj74xXGgltnX4uMG+dTPln3c+tHJn3OJBgvCeB2sZWMoV4wjLZo1XOcIszdxUY7rI3PA/2ZRm75v7Qf0Yvg5DQRUgMMlvo7Wu07mZoNLVccABndvj6nCntKaRu48YexXFWX+Y3qn8rCidH61Q8rmScdrSnYCwT0TM23GoszeCtgdShgA0/NqqTefpC90zoKISze3K0zyIfsn9+kw3JHbw+PnqSQ/z8NqG/FGiv0x4fk0FZ9yOpT+4CoVGgnCub7YEYtUGQL70GbTjPXMto+hnXK3maWzBztOQxZrHLSIdOXaLfnRE+vGEDQ29hxQJj/S9H6WbXz6Gx1UpHp8y5RjWiphHV555F/Ham1A4O1H2mK8l4b7oufB1u3cah1uQZ64xzr0VHVQnzmCm1MwQUkmF+5B/Ce9mCIqbYJlmoCQWeDVqVSpPJrZgTmcA+djqsvhTi7zbr"],"io.cncf.notary.signingAgent":"example signing agent"},"signature":"JRz9B-yzx-DLrHuwHMuR4Nqn82t2r8TxBXSnMxZfCSexcD6Q2eo8XC_OUuWwrLlwT07kE9RmoseOyp3YUVFR-VuIGr1vaL8lE8DfQTJOhMPg2AwUzqPtXrKTat8r3FYqWCDchCpUt7ZvxGCjgstqbp2xrxfFxvwfEtJgT9dhPB8C3AoFA-8ZpWRb61YH_SJNhjfsn2YmPq_YCPVH7hhgJA-7lG49whIdwNT0E4RGKa58gvxa4gA4jld1-f87Bamp_oWMiByvmZwwR_zNtnn1OoefWrld6uDW1ahr5pP56QIDLEfhYEmYk7Zf_V2HTGKZ6j6-48jgemqwdqe3moX6QeTJRhEo-MYtvhlj4Q1oCWSbfgnspX2UMelygl1MmmlUNUeeP93crE5T09hW8uFCcnOuF9gRN5yN5rgpXr68DlSMXwFZJEMvbBCEwdtYI8xQoLi9F1bIQ97RfQLwPeqXgPMkAeQOtWB238LhETP5jyHc4fuoR-w62H3n7j-quY7l"}`
}
