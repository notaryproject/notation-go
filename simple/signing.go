package simple

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/docker/libtrust"
	"github.com/notaryproject/notation-go-lib"
	"github.com/notaryproject/notation-go-lib/signature"
	x509n "github.com/notaryproject/notation-go-lib/signature/x509"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
)

type signingService struct {
	*signature.Scheme
}

// NewSigningService create a simple signing service.
func NewSigningService(signingKey libtrust.PrivateKey, signingCerts, verificationCerts []*x509.Certificate, roots *x509.CertPool) (notation.SigningService, error) {
	scheme := signature.NewScheme()

	if signingKey != nil {
		signer, err := x509n.NewSigner(signingKey, signingCerts)
		if err != nil {
			return nil, err
		}
		scheme.RegisterSigner("", signer)
	}

	verifier, err := x509n.NewVerifier(verificationCerts, roots)
	if err != nil {
		return nil, err
	}
	scheme.RegisterVerifier(verifier)

	return &signingService{
		Scheme: scheme,
	}, nil
}

func (s *signingService) Sign(ctx context.Context, desc oci.Descriptor, references ...string) ([]byte, error) {
	claims := signature.Claims{
		Manifest: signature.Manifest{
			Descriptor: convertDescriptor(desc),
			References: references,
		},
		IssuedAt: time.Now().Unix(),
	}

	sig, err := s.Scheme.Sign("", claims)
	if err != nil {
		return nil, err
	}

	return []byte(sig), nil
}

func (s *signingService) Verify(ctx context.Context, desc oci.Descriptor, sig []byte) ([]string, error) {
	claims, err := s.Scheme.Verify(string(sig))
	if err != nil {
		return nil, fmt.Errorf("verification failure: %v", err)
	}

	descriptor := convertDescriptor(desc)
	if descriptor != claims.Manifest.Descriptor {
		return nil, fmt.Errorf("verification failure: digest mismatch: %v: %v",
			descriptor,
			claims.Manifest.Descriptor,
		)
	}

	return claims.Manifest.References, nil
}

func convertDescriptor(desc oci.Descriptor) signature.Descriptor {
	return signature.Descriptor{
		MediaType: desc.MediaType,
		Digest:    desc.Digest.String(),
		Size:      desc.Size,
	}
}
