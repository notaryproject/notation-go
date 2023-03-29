package envelope

import (
	"errors"
	"fmt"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	_ "github.com/notaryproject/notation-core-go/signature/cose"
	_ "github.com/notaryproject/notation-core-go/signature/jws"
)

// MediaTypePayloadV1 is the supported content type for signature's payload.
const (
	MediaTypePayloadV1            = "application/vnd.cncf.notary.payload.v1+json"
	AnnotationX509ChainThumbprint = "io.cncf.notary.x509chain.thumbprint#S256"
)

// Payload describes the content that gets signed.
type Payload struct {
	TargetArtifact ocispec.Descriptor `json:"targetArtifact"`
}

// ValidatePayloadContentType validates signature payload's content type.
func ValidatePayloadContentType(payload *signature.Payload) error {
	switch payload.ContentType {
	case MediaTypePayloadV1:
		return nil
	default:
		return fmt.Errorf("payload content type %q not supported", payload.ContentType)
	}
}

// SanitizeTargetArtifact filters out unrelated ocispec.Descriptor fields based
// on notation spec (https://github.com/notaryproject/notaryproject/blob/main/specs/signature-specification.md#payload).
func SanitizeTargetArtifact(targetArtifact ocispec.Descriptor) ocispec.Descriptor {
	return ocispec.Descriptor{
		MediaType:   targetArtifact.MediaType,
		Digest:      targetArtifact.Digest,
		Size:        targetArtifact.Size,
		Annotations: targetArtifact.Annotations,
	}
}

// SigningTime returns the signing time of a signature envelope blob
func SigningTime(signerInfo *signature.SignerInfo) (time.Time, error) {
	// sanity check
	if signerInfo == nil {
		return time.Time{}, errors.New("failed to generate annotations: signerInfo cannot be nil")
	}
	signingTime := signerInfo.SignedAttributes.SigningTime
	if signingTime.IsZero() {
		return time.Time{}, errors.New("signing time is missing")
	}
	return signingTime.UTC(), nil
}
