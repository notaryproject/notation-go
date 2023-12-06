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

package semver

import "testing"

func TestComparePluginVersion(t *testing.T) {
	t.Run("compare with lower version", func(t *testing.T) {
		comp, err := ComparePluginVersion("1.0.0", "1.0.1")
		if err != nil || comp >= 0 {
			t.Fatal("expected nil err and negative comp")
		}
	})

	t.Run("compare with equal version", func(t *testing.T) {
		comp, err := ComparePluginVersion("1.0.1", "1.0.1")
		if err != nil || comp != 0 {
			t.Fatal("expected nil err and comp equal to 0")
		}
	})

	t.Run("failed due to invalid semantic version", func(t *testing.T) {
		expectedErrMsg := "v1.0.0 is not a valid semantic version"
		_, err := ComparePluginVersion("v1.0.0", "1.0.1")
		if err == nil || err.Error() != expectedErrMsg {
			t.Fatalf("expected err %s, but got %s", expectedErrMsg, err)
		}
	})
}
