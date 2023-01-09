package notation_test

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/notaryproject/notation-core-go/signature/cose"
	"github.com/notaryproject/notation-core-go/testhelper"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/signer"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

var (
	exampleMediaType = "application/vnd.docker.distribution.manifest.v2+json"
	exampleDigest    = digest.Digest("c0d488a800e4127c334ad20d61d7bc21b4097540327217dfab52262adc02380c")
	exampleSize      = int64(528)

	// Both COSE ("application/cose") and JWS ("application/jose+json")
	// signature mediaTypes are supported.
	exampleSignatureMediaType = "application/cose"

	// exampleCertTuple contains a RSA privateKey and a self-signed X509
	// certificate generated for demo purpose ONLY.
	// Users should bring their own full certificate chain following the
	// Notary certificate requirements:
	// https://github.com/notaryproject/notaryproject/blob/v1.0.0-rc.1/specs/signature-specification.md#certificate-requirements
	exampleCertTuple = testhelper.GetRSASelfSignedSigningCertTuple("Notation Example self-signed")
	exampleCerts     = []*x509.Certificate{exampleCertTuple.Cert}
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
}
