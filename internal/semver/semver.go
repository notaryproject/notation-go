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
	"regexp"

	"golang.org/x/mod/semver"
)

// semVerRegEx is taken from https://semver.org/#is-there-a-suggested-regular-expression-regex-to-check-a-semver-string
var semVerRegEx = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)

// IsValid returns true if version is a valid semantic version
func IsValid(version string) bool {
	return semVerRegEx.MatchString(version)
}

// ComparePluginVersion validates and compares two plugin semantic versions.
//
// The result will be 0 if v == w, -1 if v < w, or +1 if v > w.
func ComparePluginVersion(v, w string) (int, error) {
	// sanity check
	if !IsValid(v) {
		return 0, fmt.Errorf("%s is not a valid semantic version", v)
	}
	if !IsValid(w) {
		return 0, fmt.Errorf("%s is not a valid semantic version", w)
	}

	// golang.org/x/mod/semver requires semantic version strings must begin
	// with a leading "v". Adding prefix "v" to the inputs.
	// Reference: https://pkg.go.dev/golang.org/x/mod/semver#pkg-overview
	return semver.Compare("v"+v, "v"+w), nil
}
