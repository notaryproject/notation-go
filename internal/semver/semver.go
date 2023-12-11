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

// Package semver provides functions related to semanic version.
// This package is based on "golang.org/x/mod/semver"
package semver

import (
	"fmt"
	"strings"

	"golang.org/x/mod/semver"
)

// IsSemverValid returns true if version is a valid semantic version
func IsSemverValid(version string) bool {
	// a valid semanic version MUST not have prefix 'v'
	if strings.HasPrefix(version, "v") {
		return false
	}
	// golang package "golang.org/x/mod/semver" requires prefix 'v'
	return semver.IsValid("v" + version)
}

// ComparePluginVersion validates and compares two plugin semantic versions.
//
// The result will be 0 if v == w, -1 if v < w, or +1 if v > w.
func ComparePluginVersion(v, w string) (int, error) {
	// sanity check
	// a valid semantic version should not have prefix `v`
	// Reference: https://semver.org/#semantic-versioning-200
	if !IsSemverValid(v) {
		return 0, fmt.Errorf("%s is not a valid semantic version", v)
	}
	if !IsSemverValid(w) {
		return 0, fmt.Errorf("%s is not a valid semantic version", w)
	}

	// golang.org/x/mod/semver requires semantic version strings must begin
	// with a leading "v". Adding prefix "v" to the inputs.
	// Reference: https://pkg.go.dev/golang.org/x/mod/semver#pkg-overview
	return semver.Compare("v"+v, "v"+w), nil
}
