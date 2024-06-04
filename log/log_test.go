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

// Package log provides logging functionality to notation.
// Users who want to enable logging option in notation should implement the
// log.Logger interface and include it in context by calling log.WithLogger.
// 3rd party loggers that implement log.Logger: github.com/uber-go/zap.SugaredLogger
// and github.com/sirupsen/logrus.Logger.
package log

import (
	"context"
	"testing"
)

func TestWithLoggerAndGetLogger(t *testing.T) {
	tl := &discardLogger{}
	ctx := WithLogger(context.Background(), tl)

	if got := GetLogger(ctx); got != tl {
		t.Errorf("GetLogger() = %v, want %v", got, tl)
	}
}

func TestGetLoggerWithNoLogger(t *testing.T) {
	ctx := context.Background()

	if got := GetLogger(ctx); got != Discard {
		t.Errorf("GetLogger() = %v, want Discard", got)
	}
}
