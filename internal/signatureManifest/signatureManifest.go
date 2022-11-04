package signatureManifest

import (
	"github.com/notaryproject/notation-go/notation"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type SignatureManifest struct {
	Blob        ocispec.Descriptor
	Annotations map[string]string
}

func NotationDescriptorFromOCI(desc ocispec.Descriptor) notation.Descriptor {
	return notation.Descriptor{
		MediaType:   desc.MediaType,
		Digest:      desc.Digest,
		Size:        desc.Size,
		Annotations: desc.Annotations,
	}
}
