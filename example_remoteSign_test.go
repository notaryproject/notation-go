package notation_test

import (
	"context"
	"crypto/x509"
	"fmt"

	_ "github.com/notaryproject/notation-core-go/signature/cose"
	_ "github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-core-go/testhelper"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/internal/mock"
	"github.com/notaryproject/notation-go/signer"
	"github.com/opencontainers/go-digest"
)

var (
	exampleArtifactReference = "registry.acme-rockets.io/software/net-monitor@sha256:60043cf45eaebc4c0867fea485a039b598f52fd09fd5b07b0b2d2f88fad9d74e"
	exampleMediaType         = "application/vnd.docker.distribution.manifest.v2+json"
	exampleDigest            = digest.Digest("sha256:60043cf45eaebc4c0867fea485a039b598f52fd09fd5b07b0b2d2f88fad9d74e")
	exampleSize              = int64(528)

	// Both COSE ("application/cose") and JWS ("application/jose+json")
	// signature mediaTypes are supported.
	exampleSignatureMediaType = "application/cose"

	exampleRSARoot   = testhelper.GetRSARootCertificate()
	exampleCertTuple = testhelper.GetRSACertTuple(3072)
	exampleCerts     = []*x509.Certificate{exampleCertTuple.Cert, exampleRSARoot.Cert}
)

// Example_remoteSign demonstrates how to use notation.Sign to sign an artifact
// in the remote registry and push the signature to the remote.
func Example_remoteSign() {
	// exampleSigner is a notation.Signer given key and X509 certificate chain.
	exampleSigner, err := signer.New(exampleCertTuple.PrivateKey, exampleCerts)
	if err != nil {
		panic(err) // Handle error
	}

	// exampleRepo is a dummy registry.Repository for demo purpose only.
	// Users are recommended to use registry.NewRepository() for implementation
	// of registry.Repository. (https://github.com/notaryproject/notation-go/blob/main/registry/repository.go#L25)
	exampleRepo := mock.NewRepository()

	// exampleSignOptions is an example of notation.SignOptions.
	exampleSignOptions := notation.SignOptions{
		ArtifactReference:  exampleArtifactReference,
		SignatureMediaType: exampleSignatureMediaType,
	}

	// remote sign core process
	// upon successful signing, descriptor of the sign content is returned.
	targetDesc, err := notation.Sign(context.Background(), exampleSigner, exampleRepo, exampleSignOptions)
	if err != nil {
		panic(err) // Handle error
	}

	fmt.Println("Successfully signed")
	fmt.Println("targetDesc MediaType:", targetDesc.MediaType)
	fmt.Println("targetDesc Digest:", targetDesc.Digest)
	fmt.Println("targetDesc Size:", targetDesc.Size)

	// Output:
	// Successfully signed
	// targetDesc MediaType: application/vnd.docker.distribution.manifest.v2+json
	// targetDesc Digest: sha256:60043cf45eaebc4c0867fea485a039b598f52fd09fd5b07b0b2d2f88fad9d74e
	// targetDesc Size: 528
}
