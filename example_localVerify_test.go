package notation_test

import (
	"context"
	"encoding/json"
	"fmt"

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
	// examplePolicyStatement is an example of a valid trust policy statement.
	examplePolicyStatement = trustpolicy.TrustPolicy{
		Name:                  "test-statement-name",
		RegistryScopes:        []string{"registry.acme-rockets.io/software/net-monitor"},
		SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: "strict"},
		TrustStores:           []string{"ca:valid-trust-store", "signingAuthority:valid-trust-store"},
		TrustedIdentities:     []string{"x509.subject:CN=Notation Test Root,O=Notary,L=Seattle,ST=WA,C=US"},
	}

	// examplePolicyDocument is an example of a valid trust policy document.
	examplePolicyDocument = trustpolicy.Document{
		Version:       "1.0",
		TrustPolicies: []trustpolicy.TrustPolicy{examplePolicyStatement},
	}
)

// payload describes the content that gets signed.
type payload struct {
	TargetArtifact ocispec.Descriptor `json:"targetArtifact"`
}

// ExampleLocalVerify demonstrates how to use verifier.Verify to verify a
// signature of the target artifact at local (without using a
// registry.Repository).
func Example_localVerify() {
	exampleArtifactReference := "registry.acme-rockets.io/software/net-monitor@sha256:60043cf45eaebc4c0867fea485a039b598f52fd09fd5b07b0b2d2f88fad9d74e"

	exampleMediaType := "application/vnd.docker.distribution.manifest.v2+json"
	exampleDigest := digest.Digest("sha256:60043cf45eaebc4c0867fea485a039b598f52fd09fd5b07b0b2d2f88fad9d74e")
	exampleSize := int64(528)

	// changing the path of the trust store for demo purpose only.
	// Users are recommended to keep the default value, i.e. os.UserConfigDir.
	//dir.UserConfigDir = "./tmp/notation"

	exampleSignatureEnvelope := []byte(`{
		"payload": "eyJ0YXJnZXRBcnRpZmFjdCI6eyJtZWRpYVR5cGUiOiJhcHBsaWNhdGlvbi92bmQuZG9ja2VyLmRpc3RyaWJ1dGlvbi5tYW5pZmVzdC52Mitqc29uIiwiZGlnZXN0Ijoic2hhMjU2OjYwMDQzY2Y0NWVhZWJjNGMwODY3ZmVhNDg1YTAzOWI1OThmNTJmZDA5ZmQ1YjA3YjBiMmQyZjg4ZmFkOWQ3NGUiLCJzaXplIjo1Mjh9fQ",
		"protected": "eyJhbGciOiJQUzM4NCIsImNyaXQiOlsiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1NjaGVtZSIsImlvLmNuY2Yubm90YXJ5LmV4cGlyeSJdLCJjdHkiOiJhcHBsaWNhdGlvbi92bmQuY25jZi5ub3RhcnkucGF5bG9hZC52MStqc29uIiwiaW8uY25jZi5ub3RhcnkuZXhwaXJ5IjoiMjEyMC0xMS0wOVQwNzowMDowMFoiLCJpby5jbmNmLm5vdGFyeS5zaWduaW5nU2NoZW1lIjoibm90YXJ5Lng1MDkiLCJpby5jbmNmLm5vdGFyeS5zaWduaW5nVGltZSI6IjIwMjAtMTEtMDlUMDc6MDA6MDBaIn0",
		"header": {
		  "x5c": [
			"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"
		  ],
		  "io.cncf.notary.SigningAgent": "Notation/1.0.0"
		},
		"signature": "ZvsxyaSqDzS7mY_jKpnq2XtBcmyWmSE461BHL6q2pAx_-Rxr8Fvs2oIfZdSG2o3qugPDjzZDMhKdYdnrW1AIEkVIG_QUmeyGj28PVXxsC5NKpXwrPUMOzrXSFLHIvBNZ2q87wRYInsgCPtv5ZPv0IgA2sAW6y7NlVM2D0vJax55ITsJO5aEaEUlAdi_H7-TCD48DHuFpnJdNkVB_hZkwYfxuqIKU2C__Z2hLLHxaS2LzuzhqOnYlbqn4e225uZt9odXq3qmZ_44Vx3DYL_-ZuV0S9jEk7NW8-dO0T0MeQn6VXDyfT1rjc6IVPnLxAnELFyLn121GYulYC8V2D1_MLcv8sDHY23rHb3-R-WCLMDSfaIvReY89vQfxcfpdCRC0F3N2CcnrgsrUC6Fplm5Uy45Gn9--b7x5cdSzOzQsefCH1GpixW7YyNs1xZQ17WqdYyWD2EBrB5vqVFzkzDYnQ4H-p9G3AzM4HTrjWqHX-0cYHlpmTS4AjVxn0UV80Jn9"
	  }`)

	// exampleVerifyOptions is an example of notation.VerifyOptions
	exampleVerifyOptions := notation.VerifyOptions{
		ArtifactReference:  exampleArtifactReference,
		SignatureMediaType: "application/jose+json",
	}

	// exampleVerifier is an example of notation.Verifier given
	// trust policy document and X509 trust store.
	exampleVerifier, err := verifier.New(&examplePolicyDocument, truststore.NewX509TrustStore(dir.ConfigFS()), nil)
	if err != nil {
		panic(err) // Handle error
	}

	// exampleTargetDescriptor is an example of the target OCI artifact manifest
	// descriptor.
	exampleTargetDescriptor := ocispec.Descriptor{
		MediaType: exampleMediaType,
		Digest:    exampleDigest,
		Size:      exampleSize,
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
	payload := &payload{}
	err = json.Unmarshal(outcome.EnvelopeContent.Payload.Content, payload)
	if err != nil {
		panic(err) // Handle error
	}

	fmt.Println("payload content type:", outcome.EnvelopeContent.Payload.ContentType)

	// Note, upon successful verification, payload.TargetArtifact from the
	// signature envelope matches exactly with our exampleTargetDescriptor.
	// (This check has been done for the user inside verifier.Verify.)
	fmt.Println("payload.TargetArtifact MediaType:", payload.TargetArtifact.MediaType)
	fmt.Println("payload.TargetArtifact Digest:", payload.TargetArtifact.Digest)
	fmt.Println("payload.TargetArtifact Size:", payload.TargetArtifact.Size)

	// Output:
	// Successfully verified
	// payload content type: application/vnd.cncf.notary.payload.v1+json
	// payload.TargetArtifact MediaType: application/vnd.docker.distribution.manifest.v2+json
	// payload.TargetArtifact Digest: sha256:60043cf45eaebc4c0867fea485a039b598f52fd09fd5b07b0b2d2f88fad9d74e
	// payload.TargetArtifact Size: 528
}
