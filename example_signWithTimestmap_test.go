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
	"encoding/pem"
	"fmt"

	"oras.land/oras-go/v2/registry/remote"

	"github.com/notaryproject/notation-core-go/revocation"
	"github.com/notaryproject/notation-core-go/revocation/purpose"
	"github.com/notaryproject/notation-core-go/testhelper"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation-go/signer"
	"github.com/notaryproject/tspclient-go"
)

// Example_signWithTimestamp demonstrates how to use notation.Sign to sign an
// artifact with a RFC 3161 compliant timestamp countersignature and
// user trusted TSA root certificate
func Example_signWithTimestamp() {
	// exampleArtifactReference is an example of the target artifact reference
	var exampleArtifactReference = "localhost:5000/software@sha256:60043cf45eaebc4c0867fea485a039b598f52fd09fd5b07b0b2d2f88fad9d74e"

	// exampleCertTuple contains a RSA privateKey and a self-signed X509
	// certificate generated for demo purpose ONLY.
	exampleCertTuple := testhelper.GetRSASelfSignedSigningCertTuple("Notation Example self-signed")
	exampleCerts := []*x509.Certificate{exampleCertTuple.Cert}

	// exampleSigner is a notation.Signer given key and X509 certificate chain.
	// Users should replace `exampleCertTuple.PrivateKey` with their own private
	// key and replace `exampleCerts` with the corresponding full certificate
	// chain, following the Notary Project certificate requirements:
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

	// replace exampleRFC3161TSAServer with your trusted TSA server URL.
	exampleRFC3161TSAServer := "<TSA server URL>"
	httpTimestamper, err := tspclient.NewHTTPTimestamper(nil, exampleRFC3161TSAServer)
	if err != nil {
		panic(err) // Handle error
	}

	// replace exampleTSARootCertPem with your trusted TSA root cert.
	exampleTSARootCertPem := "<TSA root cert>"
	block, _ := pem.Decode([]byte(exampleTSARootCertPem))
	if block == nil {
		panic("failed to parse tsa root certificate PEM")
	}
	tsaRootCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse tsa root certificate: " + err.Error())
	}
	tsaRootCAs := x509.NewCertPool()
	tsaRootCAs.AddCert(tsaRootCert)

	// enable timestamping certificate chain revocation check
	tsaRevocationValidator, err := revocation.NewWithOptions(revocation.Options{
		CertChainPurpose: purpose.Timestamping,
	})
	if err != nil {
		panic(err) // Handle error
	}

	// exampleSignOptions is an example of notation.SignOptions.
	exampleSignOptions := notation.SignOptions{
		SignerSignOptions: notation.SignerSignOptions{
			SignatureMediaType:     exampleSignatureMediaType,
			Timestamper:            httpTimestamper,
			TSARootCAs:             tsaRootCAs,
			TSARevocationValidator: tsaRevocationValidator,
		},
		ArtifactReference: exampleArtifactReference,
	}

	targetManifestDesc, sigManifestDesc, err := notation.SignOCI(context.Background(), exampleSigner, exampleRepo, exampleSignOptions)
	if err != nil {
		panic(err) // Handle error
	}

	fmt.Println("Successfully signed")
	fmt.Println("targetManifestDesc.MediaType:", targetManifestDesc.MediaType)
	fmt.Println("targetManifestDesc.Digest:", targetManifestDesc.Digest)
	fmt.Println("targetManifestDesc.Size:", targetManifestDesc.Size)
	fmt.Println("sigManifestDesc.MediaType:", sigManifestDesc.MediaType)
	fmt.Println("sigManifestDesc.Digest:", sigManifestDesc.Digest)
	fmt.Println("sigManifestDesc.Size:", sigManifestDesc.Size)
}
