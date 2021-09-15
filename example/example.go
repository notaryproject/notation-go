package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/notaryproject/notation-go-lib"
	"github.com/notaryproject/notation-go-lib/registry"
	x509n "github.com/notaryproject/notation-go-lib/signature/x509"
	"github.com/notaryproject/notation-go-lib/simple"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Println("usage:", os.Args[0], "<key>", "<cert>", "<manifest>", "<references...>")
	}

	fmt.Println(">>> Initialize signing service")
	signing, err := getSigningService(os.Args[1], os.Args[2])
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(">>> Initialize registry service")
	ctx := context.Background()
	client := getSignatureRegistry(
		os.Getenv("notation_registry"),
		os.Getenv("notation_username"),
		os.Getenv("notation_password"),
	).Repository(ctx, os.Getenv("notation_repository"))

	fmt.Println(">>> Initialize manifest")
	references := os.Args[4:]
	manifestPath := os.Args[3]
	manifestDescriptor, err := registry.DescriptorFromFile(manifestPath)
	if err != nil {
		log.Fatal(err)
	}
	manifestDescriptor.MediaType = "application/vnd.docker.distribution.manifest.v2+json"
	fmt.Println(manifestDescriptor)

	fmt.Println(">>> Sign manifest")
	sig, err := signing.Sign(ctx, manifestDescriptor, references...)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(">>> Verify signature")
	references, err = signing.Verify(ctx, manifestDescriptor, sig)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(references)

	fmt.Println(">>> Put signature")
	signatureDescriptor, err := client.Put(ctx, sig)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(signatureDescriptor.Digest)

	fmt.Println(">>> Link signature")
	artifactDescriptor, err := client.Link(ctx, manifestDescriptor, signatureDescriptor)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(artifactDescriptor.Digest)

	fmt.Println(">>> Lookup signatures")
	signatureDigests, err := client.Lookup(ctx, manifestDescriptor.Digest)
	if err != nil {
		log.Fatal(err)
	}
	for _, signatureDigest := range signatureDigests {
		fmt.Println("-", signatureDigest)
	}

	for _, signatureDigest := range signatureDigests {
		fmt.Println(">>> Get signature:", signatureDigest)
		sig, err := client.Get(ctx, signatureDigest)
		if err != nil {
			log.Println(err)
			continue
		}

		fmt.Println(">>> Verify signature:", signatureDigest)
		references, err = signing.Verify(ctx, manifestDescriptor, sig)
		if err != nil {
			log.Println(err)
			continue
		}
		fmt.Println(references)
	}
}

func getSigningService(keyPath, certPath string) (notation.SigningService, error) {
	key, err := x509n.ReadPrivateKeyFile(keyPath)
	if err != nil {
		return nil, err
	}
	certs, err := x509n.ReadCertificateFile(certPath)
	if err != nil {
		return nil, err
	}
	rootCerts := x509.NewCertPool()
	for _, cert := range certs {
		rootCerts.AddCert(cert)
	}
	return simple.NewSigningService(key, certs, certs, rootCerts)
}

func getSignatureRegistry(name, username, password string) notation.SignatureRegistry {
	plainHTTP := username == "" // for http access
	tr := http.DefaultTransport
	if !plainHTTP {
		tr = TransportWithBasicAuth(tr, name, username, password)
	}
	return registry.NewClient(tr, name, plainHTTP)
}
