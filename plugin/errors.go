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

package plugin

import "errors"

// ErrNotCompliant is returned by plugin methods when the response is not
// compliant.
var ErrNotCompliant = errors.New("plugin not compliant")

// ErrNotRegularFile is returned when the plugin file is not an regular file.
var ErrNotRegularFile = errors.New("not regular file")

// PluginDowngradeError is returned when installing a plugin with version
// lower than the exisiting plugin version.
type PluginDowngradeError struct {
	Msg string
}

func (e PluginDowngradeError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "installing plugin with version lower than the existing plugin version"
}

// InstallEqualVersionError is returned when installing a plugin with version
// equal to the exisiting plugin version.
type InstallEqualVersionError struct {
	Msg string
}

func (e InstallEqualVersionError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "installing plugin with version equal to the existing plugin version"
}

// PluginLibraryInternalError is used when there is an issue executing a plugin
type PluginLibraryInternalError struct {
	Msg        string
	InnerError error
}

func (e PluginLibraryInternalError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	if e.InnerError != nil {
		return e.InnerError.Error()
	}
	return "plugin library internal error"
}

func (e PluginLibraryInternalError) Unwrap() error {
	return e.InnerError
}

// PluginMetadataValidationError is used when there is an issue with plugin metadata validation
type PluginMetadataValidationError struct {
	Msg        string
	InnerError error
}

func (e PluginMetadataValidationError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	if e.InnerError != nil {
		return e.InnerError.Error()
	}
	return "metadata validation error"
}

func (e PluginMetadataValidationError) Unwrap() error {
	return e.InnerError
}

// PluginProtocolError is used when there is an issue with JSON serialization/deserialization
type PluginProtocolError struct {
	Msg        string
	InnerError error
}

func (e PluginProtocolError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	if e.InnerError != nil {
		return e.InnerError.Error()
	}
	return "plugin protocol error"
}

func (e PluginProtocolError) Unwrap() error {
	return e.InnerError
}

// PluginListError is used when there is an issue with listing plugins
type PluginListError struct {
	Err error
}

func (e PluginListError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return "plugin list error"
}

func (e PluginListError) Unwrap() error {
	return errors.Unwrap(e.Err)
}
