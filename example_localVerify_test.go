package notation_test

import (
	"context"
	"fmt"

	_ "github.com/notaryproject/notation-core-go/signature/cose"
	_ "github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/internal/mock"
	"github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/notation-go/verifier/truststore"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

var (
	exampleSignatureEnvelope = mock.MockCaValidSigEnv

	exampleVerifyOptions = notation.VerifyOptions{
		ArtifactReference:  exampleArtifactReference,
		SignatureMediaType: "application/jose+json",
	}
)

func Example_localVerify() {
	dir.UserConfigDir = "./verifier/testdata"
	exampleVerifier, err := verifier.New(&examplePolicyDocument, truststore.NewX509TrustStore(dir.ConfigFS()), nil)
	if err != nil {
		panic(err) // Handle error
	}

	exampleTargetDescriptor := ocispec.Descriptor{
		MediaType: exampleMediaType,
		Digest:    exampleDigest,
		Size:      exampleSize,
	}

	_, err = exampleVerifier.Verify(context.Background(), exampleTargetDescriptor, exampleSignatureEnvelope, exampleVerifyOptions)
	if err != nil {
		panic(err) // Handle error
	}

	fmt.Println("Successfully verified")

	// Output:
	// Successfully verified
}
