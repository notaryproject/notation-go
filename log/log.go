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

import "context"

type contextKey int

// loggerKey is the associated key type for logger entry in context.
const loggerKey contextKey = iota

// Discard is a discardLogger that is used to disenable logging in notation.
var Discard Logger = &discardLogger{}

// Logger is implemented by users and/or 3rd party loggers.
// For example, github.com/uber-go/zap.SugaredLogger
// and github.com/sirupsen/logrus.Logger.
type Logger interface {
	// Debug logs a debug level message.
	Debug(args ...interface{})

	// Debugf logs a debug level message with format.
	Debugf(format string, args ...interface{})

	// Debugln logs a debug level message. Spaces are always added between
	// operands.
	Debugln(args ...interface{})

	// Info logs an info level message.
	Info(args ...interface{})

	// Infof logs an info level message with format.
	Infof(format string, args ...interface{})

	// Infoln logs an info level message. Spaces are always added between
	// operands.
	Infoln(args ...interface{})

	// Warn logs a warn level message.
	Warn(args ...interface{})

	// Warnf logs a warn level message with format.
	Warnf(format string, args ...interface{})

	// Warnln logs a warn level message. Spaces are always added between
	// operands.
	Warnln(args ...interface{})

	// Error logs an error level message.
	Error(args ...interface{})

	// Errorf logs an error level message with format.
	Errorf(format string, args ...interface{})

	// Errorln logs an error level message. Spaces are always added between
	// operands.
	Errorln(args ...interface{})
}

// WithLogger is used by callers to set the Logger in the context.
// It enables logging option in notation.
func WithLogger(ctx context.Context, logger Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

// GetLogger is used to retrieve the Logger from the context.
func GetLogger(ctx context.Context) Logger {
	if logger, ok := ctx.Value(loggerKey).(Logger); ok {
		return logger
	}
	return Discard
}

// discardLogger implements Logger but logs nothing. It is used when user
// disenabled logging option in notation, i.e. loggerKey is not in the context.
type discardLogger struct{}

func (dl *discardLogger) Debug(args ...interface{}) {
}

func (dl *discardLogger) Debugf(format string, args ...interface{}) {
}

func (dl *discardLogger) Debugln(args ...interface{}) {
}

func (dl *discardLogger) Info(args ...interface{}) {
}

func (dl *discardLogger) Infof(format string, args ...interface{}) {
}

func (dl *discardLogger) Infoln(args ...interface{}) {
}

func (dl *discardLogger) Warn(args ...interface{}) {
}

func (dl *discardLogger) Warnf(format string, args ...interface{}) {
}

func (dl *discardLogger) Warnln(args ...interface{}) {
}

func (dl *discardLogger) Error(args ...interface{}) {
}

func (dl *discardLogger) Errorf(format string, args ...interface{}) {
}

func (dl *discardLogger) Errorln(args ...interface{}) {
}
