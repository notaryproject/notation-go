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
