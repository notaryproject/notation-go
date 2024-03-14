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
	"crypto/x509"
	"fmt"

	"oras.land/oras-go/v2/registry/remote"

	"github.com/notaryproject/notation-core-go/signature/cose"
	"github.com/notaryproject/notation-core-go/testhelper"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation-go/signer"
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
	// https://github.com/notaryproject/notaryproject/blob/v1.0.0/specs/signature-specification.md#certificate-requirements
	exampleSigner, err := signer.NewGenericSigner(exampleCertTuple.PrivateKey, exampleCerts)
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
	exampleSignOptions := notation.SignOptions{
		SignerSignOptions: notation.SignerSignOptions{
			SignatureMediaType: exampleSignatureMediaType,
		},
		ArtifactReference: exampleArtifactReference,
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
