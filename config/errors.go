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

import (
	"errors"
	"fmt"
)

// ErrKeyNameEmpty is used when key name is empty.
var ErrKeyNameEmpty = errors.New("key name cannot be empty")

// KeyNotFoundError is used when key is not found in the signingkeys.json file.
type KeyNotFoundError struct {
	KeyName string
}

// Error returns the error message.
func (e KeyNotFoundError) Error() string {
	if e.KeyName != "" {
		return fmt.Sprintf("signing key %s not found", e.KeyName)
	}
	return "signing key not found"
}
