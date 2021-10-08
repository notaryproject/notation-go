// Package timestamp generates timestamping requests to TSA servers,
// and fetches the responses according to RFC 3161.
package timestamp

import "context"

// Timestamper stamps the time.
type Timestamper interface {
	// Timestamp stamps the time with the given request.
	Timestamp(context.Context, *Request) (*Response, error)
}
