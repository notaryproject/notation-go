package io

import (
	"bytes"
	"testing"
)

func TestLimitWriter(t *testing.T) {
	limit := int64(10)
	longString := "1234567891011"

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
		lw := NewLimitWriter(&buf, limit)
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

		n, err = lw.Write([]byte(longString))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n == len(longString) {
			t.Errorf("should not write more than the limit")
		}
	}
}
