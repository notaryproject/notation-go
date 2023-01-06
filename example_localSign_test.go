package notation_test

import (
	"context"
	"crypto/x509"
	"fmt"

	_ "github.com/notaryproject/notation-core-go/signature/cose"
	_ "github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-core-go/testhelper"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/signer"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

var (
	exampleMediaType = "application/vnd.docker.distribution.manifest.v2+json"
	exampleDigest    = digest.Digest("sha256:60043cf45eaebc4c0867fea485a039b598f52fd09fd5b07b0b2d2f88fad9d74e")
	exampleSize      = int64(528)

	// Both COSE ("application/cose") and JWS ("application/jose+json")
	// signature mediaTypes are supported.
	exampleSignatureMediaType = "application/cose"

	exampleCertTuple = testhelper.GetRSACertTuple(3072)
	exampleCerts     = []*x509.Certificate{exampleCertTuple.Cert, testhelper.GetRSARootCertificate().Cert}
)

// ExampleLocalSign demonstrates how to use signer.Sign to sign an artifact
// at local (without using a registry.Repository).
func Example_localSign() {
	// exampleSigner is a notation.Signer given key and X509 certificate chain.
	exampleSigner, err := signer.New(exampleCertTuple.PrivateKey, exampleCerts)
	if err != nil {
		panic(err) // Handle error
	}

	// exampleDesc is the OCI artifact manifest descriptor of the target
	// content.
	exampleDesc := ocispec.Descriptor{
		MediaType: exampleMediaType,
		Digest:    exampleDigest,
		Size:      exampleSize,
	}

	// exampleSignOptions is an example of notation.SignOptions.
	exampleSignOptions := notation.SignOptions{
		SignatureMediaType: exampleSignatureMediaType,
		SigningAgent:       "example signing agent",
	}

	// local sign core process
	// upon successful signing, signature envelope and signerInfo are returned.
	_, signerInfo, err := exampleSigner.Sign(context.Background(), exampleDesc, exampleSignOptions)
	if err != nil {
		panic(err) // Handle error
	}

	fmt.Println("Successfully signed")
	fmt.Println("signerInfo SigningAgent:", signerInfo.UnsignedAttributes.SigningAgent)

	// Output:
	// Successfully signed
	// signerInfo SigningAgent: example signing agent
}
