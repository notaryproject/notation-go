package envelope

import "github.com/notaryproject/notation-go/notation"

// MediaTypePayloadV1 is the supported content type for signature's payload.
const MediaTypePayloadV1 = "application/vnd.cncf.notary.payload.v1+json"

// SigningAgent is the unprotected header field used by signature.
var SigningAgent = "Notation/1.0.0"

// Payload describes the content that gets signed.
type Payload struct {
	TargetArtifact notation.Descriptor `json:"targetArtifact"`
}
