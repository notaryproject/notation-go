package notation_test

import (
	"context"
	"fmt"

	_ "github.com/notaryproject/notation-core-go/signature/cose"
	_ "github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/signer"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func Example_localSign() {
	// exampleSigner is a notation.Signer given key and cert chain
	exampleSigner, err := signer.New(exampleCertTuple.PrivateKey, exampleCerts)
	if err != nil {
		panic(err) // Handle error
	}

	// exampleDesc is the OCI artifact manifest descriptor of the target content
	exampleDesc := ocispec.Descriptor{
		MediaType: exampleMediaType,
		Digest:    exampleDigest,
		Size:      exampleSize,
	}

	// exampleSignOptions is an example of notation.SignOptions
	exampleSignOptions := notation.SignOptions{
		SignatureMediaType: exampleSignatureMediaType,
		SigningAgent:       "test signing agent",
	}

	_, signerInfo, err := exampleSigner.Sign(context.Background(), exampleDesc, exampleSignOptions)
	if err != nil {
		panic(err) // Handle error
	}

	fmt.Println("Successfully signed")
	fmt.Println("signerInfo SigningAgent:", signerInfo.UnsignedAttributes.SigningAgent)

	// Output:
	// Successfully signed
	// signerInfo SigningAgent: test signing agent
}
