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

// ErrPluginDowngrade is returned when installing a plugin with version
// lower than the exisiting plugin version.
type ErrPluginDowngrade struct {
	Msg string
}

func (e ErrPluginDowngrade) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "installing plugin with version lower than the existing plugin version"
}

// ErrInstallEqualVersion is returned when installing a plugin with version
// equal to the exisiting plugin version.
type ErrInstallEqualVersion struct {
	Msg string
}

func (e ErrInstallEqualVersion) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "installing plugin with version equal to the existing plugin version"
}
