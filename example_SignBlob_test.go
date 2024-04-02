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
	"fmt"
	"strings"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/signer"
)

// ExampleBlobSign demonstrates how to use signer.BlobSign to sign arbitrary data.
func Example_BlobSign() {
	//exampleSigner implements notation.Signer and notation.BlobSigner. Given key and X509 certificate chain,
	// it provides method to sign OCI artifacts or Blobs.
	// Users should replace `exampleCertTuple.PrivateKey` with their own private
	// key and replace `exampleCerts` with the corresponding certificate chain,
	//following the Notary certificate requirements:
	// https://github.com/notaryproject/notaryproject/blob/v1.0.0/specs/signature-specification.md#certificate-requirements
	exampleSigner, err := signer.NewGenericSigner(exampleCertTuple.PrivateKey, exampleCerts)
	if err != nil {
		panic(err) // Handle error
	}

	// Both COSE ("application/cose") and JWS ("application/jose+json")
	// signature mediaTypes are supported.
	exampleSignatureMediaType := jws.MediaTypeEnvelope
	exampleContentMediaType := "video/mp4"

	// exampleSignOptions is an example of notation.SignBlobOptions.
	exampleSignOptions := notation.SignBlobOptions{
		SignerSignOptions: notation.SignerSignOptions{
			SignatureMediaType: exampleSignatureMediaType,
			SigningAgent:       "example signing agent",
		},
		ContentMediaType: exampleContentMediaType,
	}

	// exampleReader reads the data that needs to be signed. This data can be in a file or in memory.
	exampleReader := strings.NewReader("example blob")

	// Upon successful signing, signature envelope and signerInfo are returned.
	// signatureEnvelope can be used in a verification process later on.
	signatureEnvelope, signerInfo, err := notation.SignBlob(context.Background(), exampleSigner, exampleReader, exampleSignOptions)
	if err != nil {
		panic(err) // Handle error
	}

	fmt.Println("Successfully signed")

	// a peek of the signature envelope generated
	sigBlob, err := signature.ParseEnvelope(exampleSignatureMediaType, signatureEnvelope)
	if err != nil {
		panic(err) // Handle error
	}
	sigContent, err := sigBlob.Content()
	if err != nil {
		panic(err) // Handle error
	}
	fmt.Println("signature Payload ContentType:", sigContent.Payload.ContentType)
	fmt.Println("signature Payload Content:", string(sigContent.Payload.Content))
	fmt.Println("signerInfo SigningAgent:", signerInfo.UnsignedAttributes.SigningAgent)

	// Output:
	// Successfully signed
	// signature Payload ContentType: application/vnd.cncf.notary.payload.v1+json
	// signature Payload Content: {"targetArtifact":{"digest":"sha384:b8ab24dafba5cf7e4c89c562f811cf10493d4203da982d3b1345f366ca863d9c2ed323dbd0fb7ff83a80302ceffa5a61","mediaType":"video/mp4","size":12}}
	// signerInfo SigningAgent: example signing agent
}
