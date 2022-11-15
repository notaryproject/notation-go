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
