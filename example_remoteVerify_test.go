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
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
)

var (
	examplePolicyStatement = trustpolicy.TrustPolicy{
		Name:                  "test-statement-name",
		RegistryScopes:        []string{"registry.acme-rockets.io/software/net-monitor"},
		SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: "strict"},
		TrustStores:           []string{"ca:valid-trust-store", "signingAuthority:valid-trust-store"},
		TrustedIdentities:     []string{"x509.subject:CN=Notation Test Root,O=Notary,L=Seattle,ST=WA,C=US"},
	}

	examplePolicyDocument = trustpolicy.Document{
		Version:       "1.0",
		TrustPolicies: []trustpolicy.TrustPolicy{examplePolicyStatement},
	}

	exampleRemoteVerifyOptions = notation.RemoteVerifyOptions{
		ArtifactReference:    exampleArtifactReference,
		MaxSignatureAttempts: 50,
	}
)

func Example_remoteVerify() {
	dir.UserConfigDir = "testdata"
	exampleVerifier, err := verifier.New(&examplePolicyDocument, truststore.NewX509TrustStore(dir.ConfigFS()), nil)
	if err != nil {
		panic(err) // Handle error
	}

	// exampleRepo is a dummy registry.Repository for demo purpose.
	// Users are recommended to use registry.NewRepository() for implementation
	// of registry.Repository. (https://github.com/notaryproject/notation-go/blob/main/registry/repository.go#L25)
	exampleRepo := mock.NewRepository()

	targetDesc, _, err := notation.Verify(context.Background(), exampleVerifier, exampleRepo, exampleRemoteVerifyOptions)
	if err != nil {
		panic(err) // Handle error
	}
	fmt.Println("targetDesc MediaType:", targetDesc.MediaType)
	fmt.Println("targetDesc Digest:", targetDesc.Digest)
	fmt.Println("targetDesc Size:", targetDesc.Size)

	// Output:
	// targetDesc MediaType: application/vnd.docker.distribution.manifest.v2+json
	// targetDesc Digest: sha256:60043cf45eaebc4c0867fea485a039b598f52fd09fd5b07b0b2d2f88fad9d74e
	// targetDesc Size: 528
}
