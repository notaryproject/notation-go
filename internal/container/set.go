package set

// Set is a map as a set data structure.
type Set[T comparable] map[T]struct{}

// Add adds the element of type T into the Set.
func (s Set[T]) Add(elem T) {
	s[elem] = struct{}{}
}

// Contains checks if element exists in the Set.
func (s Set[T]) Contains(elem T) bool {
	if _, ok := s[elem]; ok {
		return true
	}

	return false
}

// New creats an empty Set for elements of type T.
func New[T comparable]() Set[T] {
	return make(map[T]struct{})
}
