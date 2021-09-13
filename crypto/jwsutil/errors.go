package jwsutil

import "errors"

var (
	ErrInvalidCompactSerialization = errors.New("invalid compact serialization")
	ErrInvalidJSONSerialization    = errors.New("invalid JSON serialization")
)
