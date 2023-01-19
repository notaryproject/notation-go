package notation_test

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/notaryproject/notation-core-go/signature/cose"
	"github.com/notaryproject/notation-core-go/testhelper"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation-go/signer"
	"oras.land/oras-go/v2/registry/remote"
)

// Both COSE ("application/cose") and JWS ("application/jose+json")
// signature mediaTypes are supported.
var exampleSignatureMediaType = cose.MediaTypeEnvelope

// ExampleRemoteSign demonstrates how to use notation.Sign to sign an artifact
// in the remote registry and push the signature to the remote.
func Example_remoteSign() {
	// exampleArtifactReference is an example of the target artifact reference
	var exampleArtifactReference = "localhost:5000/software@sha256:60043cf45eaebc4c0867fea485a039b598f52fd09fd5b07b0b2d2f88fad9d74e"

	// exampleCertTuple contains a RSA privateKey and a self-signed X509
	// certificate generated for demo purpose ONLY.
	exampleCertTuple := testhelper.GetRSASelfSignedSigningCertTuple("Notation Example self-signed")
	exampleCerts := []*x509.Certificate{exampleCertTuple.Cert}

	// exampleSigner is a notation.Signer given key and X509 certificate chain.
	// Users should replace `exampleCertTuple.PrivateKey` with their own private
	// key and replace `exampleCerts` with the corresponding full certificate
	// chain, following the Notary certificate requirements:
	// https://github.com/notaryproject/notaryproject/blob/v1.0.0-rc.1/specs/signature-specification.md#certificate-requirements
	exampleSigner, err := signer.New(exampleCertTuple.PrivateKey, exampleCerts)
	if err != nil {
		panic(err) // Handle error
	}

	// exampleRepo is an example of registry.Repository.
	remoteRepo, err := remote.NewRepository(exampleArtifactReference)
	if err != nil {
		panic(err) // Handle error
	}
	exampleRepo := registry.NewRepository(remoteRepo)

	// exampleSignOptions is an example of notation.SignOptions.
	exampleSignOptions := notation.RemoteSignOptions{
		ArtifactReference:  exampleArtifactReference,
		SignatureMediaType: exampleSignatureMediaType,
	}

	// remote sign core process
	// upon successful signing, descriptor of the sign content is returned and
	// the generated signature is pushed into remote registry.
	targetDesc, err := notation.Sign(context.Background(), exampleSigner, exampleRepo, exampleSignOptions)
	if err != nil {
		panic(err) // Handle error
	}

	fmt.Println("Successfully signed")
	fmt.Println("targetDesc MediaType:", targetDesc.MediaType)
	fmt.Println("targetDesc Digest:", targetDesc.Digest)
	fmt.Println("targetDesc Size:", targetDesc.Size)
}
