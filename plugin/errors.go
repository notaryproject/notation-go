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
var ErrNotRegularFile = errors.New("plugin executable file is not a regular file")

// PluginDowngradeError is returned when installing a plugin with version
// lower than the exisiting plugin version.
type PluginDowngradeError struct {
	Msg string
}

// Error returns the error message.
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

// Error returns the error message.
func (e InstallEqualVersionError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "installing plugin with version equal to the existing plugin version"
}

// PluginMalformedError is used when there is an issue with plugin and
// should be fixed by plugin developers.
type PluginMalformedError struct {
	Msg        string
	InnerError error
}

// Error returns the error message.
func (e PluginMalformedError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return e.InnerError.Error()
}

// Unwrap returns the inner error.
func (e PluginMalformedError) Unwrap() error {
	return e.InnerError
}

// PluginDirectoryWalkError is used when there is an issue with plugins directory
// and should suggest user to check the permission of plugin directory.
type PluginDirectoryWalkError error

// PluginExecutableFileError is used when there is an issue with plugin
// executable file and should suggest user to check the existence, permission
// and platform/arch compatibility of plugin.
type PluginExecutableFileError struct {
	Msg        string
	InnerError error
}

// Error returns the error message.
func (e PluginExecutableFileError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return e.InnerError.Error()
}

// Unwrap returns the inner error.
func (e PluginExecutableFileError) Unwrap() error {
	return e.InnerError
}
