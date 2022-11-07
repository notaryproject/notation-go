//go:build !windows
// +build !windows

package plugin

func binName(name string) string {
	return prefix + name
}
