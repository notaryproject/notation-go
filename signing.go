package notation

import (
	"context"

	oci "github.com/opencontainers/image-spec/specs-go/v1"
)

// SigningService provides signature signing and verification services.
type SigningService interface {
	Sign(ctx context.Context, desc oci.Descriptor, references ...string) ([]byte, error)
	Verify(ctx context.Context, desc oci.Descriptor, signature []byte) ([]string, error)
}
