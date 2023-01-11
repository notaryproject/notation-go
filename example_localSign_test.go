package notation_test

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/notaryproject/notation-core-go/signature/cose"
	"github.com/notaryproject/notation-core-go/testhelper"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/signer"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

var (
	// exampleDesc is an example of the target OCI artifact manifest descriptor.
	exampleDesc = ocispec.Descriptor{
		MediaType: "application/vnd.docker.distribution.manifest.v2+json",
		Digest:    "sha256:c0d488a800e4127c334ad20d61d7bc21b4097540327217dfab52262adc02380c",
		Size:      528,
	}

	// exampleCertTuple contains a RSA privateKey and a self-signed X509
	// certificate generated for demo purpose ONLY.
	exampleCertTuple = testhelper.GetRSASelfSignedSigningCertTuple("Notation Example self-signed")
	exampleCerts     = []*x509.Certificate{exampleCertTuple.Cert}
)

// ExampleLocalSign demonstrates how to use signer.Sign to sign an artifact
// at local (without using a registry.Repository).
func Example_localSign() {
	// exampleSigner is a notation.Signer given key and X509 certificate chain.
	// Users should replace `exampleCertTuple.PrivateKey` with their own private
	// key and replace `exampleCerts` with the corresponding full certificate
	// chain, following the Notary certificate requirements:
	// https://github.com/notaryproject/notaryproject/blob/v1.0.0-rc.1/specs/signature-specification.md#certificate-requirements
	exampleSigner, err := signer.New(exampleCertTuple.PrivateKey, exampleCerts)
	if err != nil {
		panic(err) // Handle error
	}

	// Both COSE ("application/cose") and JWS ("application/jose+json")
	// signature mediaTypes are supported.
	exampleSignatureMediaType := cose.MediaTypeEnvelope

	// exampleSignOptions is an example of notation.SignOptions.
	exampleSignOptions := notation.SignOptions{
		SignatureMediaType: exampleSignatureMediaType,
		SigningAgent:       "example signing agent",
	}

	// local sign core process
	// upon successful signing, signature envelope and signerInfo are returned.
	// signatureEnvelope can be used in a verification process later on.
	signatureEnvelope, signerInfo, err := exampleSigner.Sign(context.Background(), exampleDesc, exampleSignOptions)
	if err != nil {
		panic(err) // Handle error
	}

	fmt.Println("Successfully signed")

	// a peek of the signature envelope generated from Sign
	// for JWS format, this should be `jws.ParseEnvelope(signatureEnvelope)`
	sigBlob, err := cose.ParseEnvelope(signatureEnvelope)
	if err != nil {
		panic(err) // Handle error
	}
	sigContent, err := sigBlob.Content()
	if err != nil {
		panic(err) // Handle error
	}
	fmt.Println("signature Payload ContentType:", sigContent.Payload.ContentType)

	fmt.Println("signerInfo SigningAgent:", signerInfo.UnsignedAttributes.SigningAgent)

	// Output:
	// Successfully signed
	// signature Payload ContentType: application/vnd.cncf.notary.payload.v1+json
	// signerInfo SigningAgent: example signing agent
}
