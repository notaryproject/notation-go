package envelope

import (
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Payload describes the content that gets signed.
type Payload struct {
	TargetArtifact ocispec.Descriptor `json:"targetArtifact"`
}
