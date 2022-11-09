package slice

// ContainsString is a utility function to check if a string exists in an array
func ContainsString(val string, values []string) bool {
	for _, v := range values {
		if v == val {
			return true
		}
	}
	return false
}
