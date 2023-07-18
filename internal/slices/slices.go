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

package slices

// Contains reports whether v is present in s.
func Contains[E comparable](s []E, v E) bool {
	for _, vs := range s {
		if v == vs {
			return true
		}
	}
	return false
}

// ContainsAny reports whether v is present in s
func ContainsAny(s []any, v any) bool {
	for _, vs := range s {
		if vs == v {
			return true
		}
	}
	return false
}

// Delete removes element at index i from slice s and
// returns the modified slice.
func Delete[T any](s []T, i int) []T {
	return append(s[:i], s[i+1:]...)
}

type isser interface {
	Is(string) bool
}

// IndexIsser returns the index of the first occurrence of name in s,
// or -1 if not present.
func IndexIsser[E isser](s []E, name string) int {
	for i, v := range s {
		if v.Is(name) {
			return i
		}
	}
	return -1
}

// ContainsIsser reports whether name is present in s.
func ContainsIsser[E isser](s []E, name string) bool {
	return IndexIsser(s, name) >= 0
}
