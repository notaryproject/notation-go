package slice

const (
	Wildcard    = "*"
	X509Subject = "x509.subject"
)

// Contains is a utility function to check if a string exists in an array
func Contains(val string, values []string) bool {
	for _, v := range values {
		if v == val {
			return true
		}
	}
	return false
}
