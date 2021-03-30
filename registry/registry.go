package registry

import (
	"context"
	"fmt"
	"net/http"

	"github.com/notaryproject/notary/v2"
)

type registry struct {
	tr   http.RoundTripper
	base string
}

// NewClient creates a client to the remote registry
// for accessing the signatures.
func NewClient(tr http.RoundTripper, name string, plainHTTP bool) notary.SignatureRegistry {
	scheme := "https"
	if plainHTTP {
		scheme = "http"
	}
	return &registry{
		tr:   tr,
		base: fmt.Sprintf("%s://%s/v2", scheme, name),
	}
}

func (r *registry) Repository(ctx context.Context, name string) notary.SignatureRepository {
	return &repository{
		tr:   r.tr,
		base: r.base,
		name: name,
	}
}
