package timestamp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// maxBodyLength specifies the max content can be received from the possibly malicious
// remote server.
// The legnth of a regular TSA response with certificates is usually less than 10 KiB.
const maxBodyLength = 1 * 1024 * 1024 // 1 MiB

// httpTimestamper is a HTTP-based timestamper.
type httpTimestamper struct {
	rt       http.RoundTripper
	endpoint string
}

// NewHTTPTimestamper creates a HTTP-based timestamper with the endpoint provided by the TSA.
// http.DefaultTransport is used if nil RoundTripper is passed.
func NewHTTPTimestamper(rt http.RoundTripper, endpoint string) (Timestamper, error) {
	if rt == nil {
		rt = http.DefaultTransport
	}
	if _, err := url.Parse(endpoint); err != nil {
		return nil, err
	}
	return &httpTimestamper{
		rt:       rt,
		endpoint: endpoint,
	}, nil
}

// Timestamp sends the request to the remote TSA server for timestamping.
// Reference: RFC 3161 3.4 Time-Stamp Protocol via HTTP
func (ts *httpTimestamper) Timestamp(ctx context.Context, req *Request) (*Response, error) {
	// prepare for http request
	reqBytes, err := req.MarshalBinary()
	if err != nil {
		return nil, err
	}
	hReq, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.endpoint, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, err
	}
	hReq.Header.Set("Content-Type", "application/timestamp-query")

	// send the request to the remote TSA server
	hResp, err := ts.rt.RoundTrip(hReq)
	if err != nil {
		return nil, err
	}
	defer hResp.Body.Close()

	// verify HTTP response
	if hResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %s", hResp.Status)
	}
	if contentType := hResp.Header.Get("Content-Type"); contentType != "application/timestamp-reply" {
		return nil, fmt.Errorf("unexpected response content type: %s", contentType)
	}

	// read response
	body := io.LimitReader(hResp.Body, maxBodyLength)
	respBytes, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	var resp Response
	if err := resp.UnmarshalBinary(respBytes); err != nil {
		return nil, err
	}
	return &resp, nil
}
