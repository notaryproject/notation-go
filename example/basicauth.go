package main

import (
	"net/http"
)

type transportWithBasicAuth struct {
	base     http.RoundTripper
	hostname string
	username string
	password string
}

// TransportWithBasicAuth returns the specified transport with basic auth
func TransportWithBasicAuth(tr http.RoundTripper, hostname, username, password string) http.RoundTripper {
	return &transportWithBasicAuth{
		base:     tr,
		hostname: hostname,
		username: username,
		password: password,
	}
}

func (tr *transportWithBasicAuth) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Host == tr.hostname {
		req.SetBasicAuth(tr.username, tr.password)
	}
	return tr.base.RoundTrip(req)
}
