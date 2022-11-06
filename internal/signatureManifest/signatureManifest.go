package signatureManifest

import (
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type SignatureManifest struct {
	Blob        ocispec.Descriptor
	Annotations map[string]string
}
