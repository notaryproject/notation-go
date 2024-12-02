// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package io

import (
	"bytes"
	"errors"
	"testing"
)

func TestLimitWriter(t *testing.T) {
	limit := int64(10)

	tests := []struct {
		input    string
		expected string
		written  int
	}{
		{"hello", "hello", 5},
		{" world", " world", 6},
		{"!", "!", 1},
		{"1234567891011", "1234567891", 10},
	}

	for _, tt := range tests {
		var buf bytes.Buffer
		lw := LimitWriter(&buf, limit)
		n, err := lw.Write([]byte(tt.input))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n != tt.written {
			t.Errorf("expected %d bytes written, got %d", tt.written, n)
		}
		if buf.String() != tt.expected {
			t.Errorf("expected buffer %q, got %q", tt.expected, buf.String())
		}
	}
}

func TestLimitWriterFailed(t *testing.T) {
	limit := int64(10)
	longString := "1234567891011"

	var buf bytes.Buffer
	lw := LimitWriter(&buf, limit)
	_, err := lw.Write([]byte(longString))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = lw.Write([]byte(longString))
	expectedErr := errors.New("write limit exceeded")
	if err.Error() != expectedErr.Error() {
		t.Errorf("expected error %v, got %v", expectedErr, err)
	}
}
