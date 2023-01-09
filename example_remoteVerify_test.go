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

// ExampleRemoteVerify demonstrates how to use notation.Verify to verify
// signatures of an artifact in the remote registry.
func Example_remoteVerify() {
	exampleArtifactReference := "registry.acme-rockets.io/software/net-monitor@sha256:60043cf45eaebc4c0867fea485a039b598f52fd09fd5b07b0b2d2f88fad9d74e"

	// exampleRemoteVerifyOptions is an example of notation.RemoteVerifyOptions.
	exampleRemoteVerifyOptions := notation.RemoteVerifyOptions{
		ArtifactReference:    exampleArtifactReference,
		MaxSignatureAttempts: 50,
	}

	// examplePolicyStatement is an example of a valid trust policy statement.
	examplePolicyStatement := trustpolicy.TrustPolicy{
		Name:                  "test-statement-name",
		RegistryScopes:        []string{"registry.acme-rockets.io/software/net-monitor"},
		SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: "strict"},
		TrustStores:           []string{"ca:valid-trust-store"},
		TrustedIdentities:     []string{"x509.subject:CN=Notation Test Root,O=Notary,L=Seattle,ST=WA,C=US"},
	}

	// examplePolicyDocument is an example of a valid trust policy document.
	// trust policy document should follow this spec:
	// https://github.com/notaryproject/notaryproject/blob/v1.0.0-rc.1/specs/trust-store-trust-policy.md#trust-policy
	examplePolicyDocument := trustpolicy.Document{
		Version:       "1.0",
		TrustPolicies: []trustpolicy.TrustPolicy{examplePolicyStatement},
	}

	// changing the path of the trust store for demo purpose ONLY.
	// Users could keep the default value, i.e. os.UserConfigDir.
	dir.UserConfigDir = "./verifier/testdata"

	// exampleVerifier is an example of notation.Verifier given
	// trust policy document and X509 trust store.
	exampleVerifier, err := verifier.New(&examplePolicyDocument, truststore.NewX509TrustStore(dir.ConfigFS()), nil)
	if err != nil {
		panic(err) // Handle error
	}

	// exampleRepo is a dummy registry.Repository for demo purpose ONLY.
	// Users are recommended to use registry.NewRepository() for implementation
	// of registry.Repository. (https://github.com/notaryproject/notation-go/blob/v1.0.0-rc.1/registry/repository.go#L25)
	exampleRepo := mock.NewRepository()

	// remote verify core process
	// upon successful verification, the target OCI artifact manifest descriptor
	// and signature verification outcome are returned.
	targetDesc, _, err := notation.Verify(context.Background(), exampleVerifier, exampleRepo, exampleRemoteVerifyOptions)
	if err != nil {
		panic(err) // Handle error
	}

	fmt.Println("Successfully verified")
	fmt.Println("targetDesc MediaType:", targetDesc.MediaType)
	fmt.Println("targetDesc Digest:", targetDesc.Digest)
	fmt.Println("targetDesc Size:", targetDesc.Size)

	// Output:
	// Successfully verified
	// targetDesc MediaType: application/vnd.docker.distribution.manifest.v2+json
	// targetDesc Digest: sha256:60043cf45eaebc4c0867fea485a039b598f52fd09fd5b07b0b2d2f88fad9d74e
	// targetDesc Size: 528
}
