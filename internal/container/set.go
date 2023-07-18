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

package set

// Set is a map as a set data structure.
type Set[T comparable] map[T]struct{}

// Add adds the element of type T into the Set.
func (s Set[T]) Add(elem T) {
	s[elem] = struct{}{}
}

// Contains checks if element exists in the Set.
func (s Set[T]) Contains(elem T) bool {
	_, ok := s[elem]

	return ok
}

// New creates an empty Set for elements of type T.
func New[T comparable]() Set[T] {
	return make(map[T]struct{})
}

// NewWithSize creates an empty Set of fixed size for elements of type T.
func NewWithSize[T comparable](size int) Set[T] {
	return make(map[T]struct{}, size)
}
