package notation_test

import (
	"context"
	"encoding/json"
	"fmt"

	_ "github.com/notaryproject/notation-core-go/signature/cose"
	_ "github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/internal/envelope"
	"github.com/notaryproject/notation-go/internal/mock"
	"github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/notation-go/verifier/truststore"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

var (
	// exampleSignatureEnvelope is an example of a valid signature envelope
	exampleSignatureEnvelope = mock.MockCaValidSigEnv

	// exampleVerifyOptions is an example of notation.VerifyOptions
	exampleVerifyOptions = notation.VerifyOptions{
		ArtifactReference:  exampleArtifactReference,
		SignatureMediaType: "application/jose+json",
	}
)

// ExampleLocalVerify demonstrates how to use verifier.Verify to verify a
// signature of the target artifact at local (without using a
// registry.Repository).
func Example_localVerify() {
	// changing the path of the trust store for demo purpose only.
	// Users are recommended to keep the default value, i.e. os.UserConfigDir.
	dir.UserConfigDir = "./verifier/testdata"

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
	payload := &envelope.Payload{}
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
