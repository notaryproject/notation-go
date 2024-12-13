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

// Package io provides a LimitWriter that writes to an underlying writer up to
// a limit.

package io

import (
	"errors"
	"io"
)

// ErrLimitExceeded is returned when the write limit is exceeded.
var ErrLimitExceeded = errors.New("write limit exceeded")

// LimitedWriter is a writer that writes to an underlying writer up to a limit.
type LimitedWriter struct {
	W io.Writer // underlying writer
	N int64     // remaining bytes
}

// LimitWriter returns a new LimitWriter that writes to w.
//
// parameters:
// w: the writer to write to
// limit: the maximum number of bytes to write
func LimitWriter(w io.Writer, limit int64) *LimitedWriter {
	return &LimitedWriter{W: w, N: limit}
}

// Write writes p to the underlying writer up to the limit.
func (l *LimitedWriter) Write(p []byte) (int, error) {
	if l.N <= 0 {
		return 0, ErrLimitExceeded
	}
	if int64(len(p)) > l.N {
		p = p[:l.N]
	}
	n, err := l.W.Write(p)
	l.N -= int64(n)
	return n, err
}
