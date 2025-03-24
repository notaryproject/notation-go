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

package config

import "testing"

func TestErrorKeyNotFound(t *testing.T) {
	e := ErrorKeyNotFound{}
	if e.Error() != "signing key not found" {
		t.Fatalf("ErrorKeyNotFound.Error() = %v, want %v", e.Error(), "signing key not found")
	}

	e = ErrorKeyNotFound{KeyName: "testKey"}
	if e.Error() != `signing key testKey not found` {
		t.Fatalf("ErrorKeyNotFound.Error() = %v, want %v", e.Error(), "key not found")
	}
}
