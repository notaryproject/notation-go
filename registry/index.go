package registry

import oci "github.com/opencontainers/image-spec/specs-go/v1"

// Index references manifests and signatures
type Index struct {
	oci.Index
	MediaType string         `json:"mediaType"`
	Config    oci.Descriptor `json:"config"`
}
