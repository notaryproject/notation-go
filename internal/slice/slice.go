package slice

// Contains reports whether v is present in s.
func Contains[E comparable](s []E, v E) bool {
	for _, vs := range s {
		if v == vs {
			return true
		}
	}
	return false
}

// ContainsAny reports whether val is present in values
func ContainsAny(values []interface{}, val interface{}) bool {
	for _, v := range values {
		if v == val {
			return true
		}
	}
	return false
}
