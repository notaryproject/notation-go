package registry

import (
	"fmt"
	"io"

	"github.com/opencontainers/go-digest"
)

const maxReadLimit = 4 * 1024 * 1024

func readAllVerified(r io.Reader, expected digest.Digest) ([]byte, error) {
	digester := expected.Algorithm().Digester()
	content, err := io.ReadAll(io.TeeReader(
		io.LimitReader(r, maxReadLimit),
		digester.Hash(),
	))
	if err != nil {
		return nil, err
	}
	if len(content) == maxReadLimit {
		return nil, fmt.Errorf("reached max read limit %d", maxReadLimit)
	}
	if actual := digester.Digest(); actual != expected {
		return nil, fmt.Errorf("mismatch digest: expect %v: got %v", expected, actual)
	}
	return content, nil
}
