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
