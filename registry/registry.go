package registry

import (
	"context"
	"fmt"
	"net/http"

	"github.com/notaryproject/notation-go-lib"
)

type registry struct {
	tr   http.RoundTripper
	base string
}

// NewClient creates a client to the remote registry
// for accessing the signatures.
func NewClient(tr http.RoundTripper, name string, plainHTTP bool) notation.SignatureRegistry {
	scheme := "https"
	if plainHTTP {
		scheme = "http"
	}
	return &registry{
		tr:   tr,
		base: fmt.Sprintf("%s://%s", scheme, name),
	}
}

func (r *registry) Repository(ctx context.Context, name string) notation.SignatureRepository {
	return &repository{
		tr:   r.tr,
		base: r.base,
		name: name,
	}
}
