package registry

import (
	"github.com/opencontainers/image-spec/specs-go"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
)

// Artifact references manifests and signatures
type Artifact struct {
	specs.Versioned
	MediaType    string           `json:"mediaType"`
	ArtifactType string           `json:"artifactType"`
	Config       oci.Descriptor   `json:"config"`
	Blobs        []oci.Descriptor `json:"blobs"`
	DependsOn    []oci.Descriptor `json:"dependsOn"`
}
