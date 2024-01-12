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

// PluginUnknownError is used when there is an issue executing a plugin
// and should be reported to Notation developers.
type PluginUnknownError struct {
	Msg        string
	InnerError error
}

func (e PluginUnknownError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	if e.InnerError != nil {
		return e.InnerError.Error()
	}
	return "plugin unknown error"
}

func (e PluginUnknownError) Unwrap() error {
	return e.InnerError
}

// PluginValidityError is used when there is an issue with plugin validity and
// should be fixed by plugin developers.
type PluginValidityError struct {
	Msg        string
	InnerError error
}

func (e PluginValidityError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	if e.InnerError != nil {
		return e.InnerError.Error()
	}
	return "plugin validity error"
}

func (e PluginValidityError) Unwrap() error {
	return e.InnerError
}

// PluginDirectoryError is used when there is an issue with plugins directory
// and should suggest user to check the plugin directory.
type PluginDirectoryError struct {
	Err error
}

func (e PluginDirectoryError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return "plugin directory error"
}

func (e PluginDirectoryError) Unwrap() error {
	return errors.Unwrap(e.Err)
}
