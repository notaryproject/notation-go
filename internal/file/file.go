package file

import "regexp"

// IsValidFileName checks if a file name is cross-platform compatible
func IsValidFileName(fileName string) bool {
	return regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`).MatchString(fileName)
}
