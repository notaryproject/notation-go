package timestamp

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/notaryproject/notation-go-lib/internal/crypto/pki"
)

var testRequest = []byte{
	// Request
	0x30, 0x37,

	// Version
	0x02, 0x01, 0x01,

	// MessageImprint
	0x30, 0x2f,

	// MessageImprint.HashAlgorithm
	0x30, 0x0b,

	// MessageImprint.HashAlgorithm.Algorithm
	0x06, 0x09,
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,

	// MessageImprint.HashedMessage
	0x04, 0x20,
	0x83, 0x26, 0xf4, 0x70, 0x9d, 0x40, 0x1d, 0xfa, 0xbf, 0xa7, 0x83, 0x02, 0xfb, 0x1c, 0xde, 0xa0,
	0xf1, 0x80, 0x48, 0xa4, 0x40, 0x40, 0xc2, 0x12, 0xbd, 0x8e, 0x28, 0xda, 0x6b, 0xc6, 0x51, 0xc7,

	// CertReq
	0x01, 0x01, 0xff,
}

func TestHTTPTimestampGranted(t *testing.T) {
	// setup test server
	testResp, err := os.ReadFile("testdata/granted.tsq")
	if err != nil {
		t.Fatal("failed to read test response:", err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const wantContentType = "application/timestamp-query"
		if got := r.Header.Get("Content-Type"); got != wantContentType {
			t.Fatalf("TimeStampRequest.ContentType = %v, want %v", err, wantContentType)
		}
		if got, err := io.ReadAll(r.Body); err != nil {
			t.Fatalf("TimeStampRequest.Body read error = %v", err)
		} else if !bytes.Equal(got, testRequest) {
			t.Fatalf("TimeStampRequest.Body = %v, want %v", got, testRequest)
		}

		// write reply
		w.Header().Set("Content-Type", "application/timestamp-reply")
		if _, err := w.Write(testResp); err != nil {
			t.Error("failed to write response:", err)
		}
	}))
	defer ts.Close()

	// do timestamp
	tsa := NewHTTPTimestamper(nil, ts.URL)
	message := []byte("notation")
	req, err := NewRequestFromBytes(message)
	if err != nil {
		t.Fatalf("NewRequestFromString() error = %v", err)
	}
	ctx := context.Background()
	resp, err := tsa.Timestamp(ctx, req)
	if err != nil {
		t.Fatalf("httpTimestamper.Timestamp() error = %v", err)
	}
	wantStatus := pki.StatusGranted
	if got := resp.Status.Status; got != wantStatus {
		t.Fatalf("Response.Status = %v, want %v", got, wantStatus)
	}

	// verify timestamp token
	token, err := resp.SignedToken()
	if err != nil {
		t.Fatalf("Response.SignedToken() error = %v", err)
	}
	roots := x509.NewCertPool()
	rootCABytes, err := os.ReadFile("testdata/GlobalSignRootCA.crt")
	if err != nil {
		t.Fatal("failed to read root CA certificate:", err)
	}
	if ok := roots.AppendCertsFromPEM(rootCABytes); !ok {
		t.Fatal("failed to load root CA certificate")
	}
	opts := x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	if _, err := token.Verify(opts); err != nil {
		t.Fatal("SignedToken.Verify() error =", err)
	}
	info, err := token.Info()
	if err != nil {
		t.Fatal("SignedToken.Info() error =", err)
	}
	if err := info.Verify(message); err != nil {
		t.Errorf("TSTInfo.Verify() error = %v", err)
	}
	timestamp, accuracy := info.Timestamp()
	wantTimestamp := time.Date(2021, 9, 18, 11, 54, 34, 0, time.UTC)
	if timestamp != wantTimestamp {
		t.Errorf("TSTInfo.Timestamp() Timestamp = %v, want %v", timestamp, wantTimestamp)
	}
	wantAccuracy := time.Second
	if accuracy != wantAccuracy {
		t.Errorf("TSTInfo.Timestamp() Accuracy = %v, want %v", accuracy, wantAccuracy)
	}
}

func TestHTTPTimestampRejection(t *testing.T) {
	// setup test server
	testResp, err := os.ReadFile("testdata/rejection.tsq")
	if err != nil {
		t.Fatal("failed to read test response:", err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const wantContentType = "application/timestamp-query"
		if got := r.Header.Get("Content-Type"); got != wantContentType {
			t.Fatalf("TimeStampRequest.ContentType = %v, want %v", err, wantContentType)
		}
		if got, err := io.ReadAll(r.Body); err != nil {
			t.Fatalf("TimeStampRequest.Body read error = %v", err)
		} else if !bytes.Equal(got, testRequest) {
			t.Fatalf("TimeStampRequest.Body = %v, want %v", got, testRequest)
		}

		// write reply
		w.Header().Set("Content-Type", "application/timestamp-reply")
		if _, err := w.Write(testResp); err != nil {
			t.Error("failed to write response:", err)
		}
	}))
	defer ts.Close()

	// do timestamp
	tsa := NewHTTPTimestamper(nil, ts.URL)
	message := []byte("notation")
	req, err := NewRequestFromBytes(message)
	if err != nil {
		t.Fatalf("NewRequestFromString() error = %v", err)
	}
	ctx := context.Background()
	resp, err := tsa.Timestamp(ctx, req)
	if err != nil {
		t.Fatalf("httpTimestamper.Timestamp() error = %v", err)
	}
	wantStatus := pki.StatusRejection
	if got := resp.Status.Status; got != wantStatus {
		t.Fatalf("Response.Status = %v, want %v", got, wantStatus)
	}
	wantStatusString := []string{"request contains unknown algorithm"}
	if got := resp.Status.StatusString; !reflect.DeepEqual(got, wantStatusString) {
		t.Fatalf("Response.StatusString = %v, want %v", got, wantStatusString)
	}
	wantFailInfo := asn1.BitString{
		Bytes:     []byte{0x80},
		BitLength: 1,
	}
	if got := resp.Status.FailInfo; !reflect.DeepEqual(got, wantFailInfo) {
		t.Fatalf("Response.FailInfo = %v, want %v", got, wantFailInfo)
	}
}

func TestHTTPTimestampBadEndpoint(t *testing.T) {
	// setup test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// write reply
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if _, err := w.Write([]byte("{}")); err != nil {
			t.Error("failed to write response:", err)
		}
	}))
	defer ts.Close()

	// do timestamp
	tsa := NewHTTPTimestamper(nil, ts.URL)
	req, err := NewRequestFromString("notation")
	if err != nil {
		t.Fatalf("NewRequestFromString() error = %v", err)
	}
	ctx := context.Background()
	_, err = tsa.Timestamp(ctx, req)
	if err == nil {
		t.Fatalf("httpTimestamper.Timestamp() error = %v, wantErr %v", err, true)
	}
}

func TestHTTPTimestampEndpointNotFound(t *testing.T) {
	// setup test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	// do timestamp
	tsa := NewHTTPTimestamper(nil, ts.URL)
	req, err := NewRequestFromString("notation")
	if err != nil {
		t.Fatalf("NewRequestFromString() error = %v", err)
	}
	ctx := context.Background()
	_, err = tsa.Timestamp(ctx, req)
	if err == nil {
		t.Fatalf("httpTimestamper.Timestamp() error = %v, wantErr %v", err, true)
	}
}
