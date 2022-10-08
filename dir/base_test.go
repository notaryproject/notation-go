package dir

import (
	"errors"
	"strings"
	"testing"
)

func TestLoadPath(t *testing.T) {
	tests := []struct {
		name              string
		os                string
		userConfigDir     func() (string, error)
		userCacheDir      func() (string, error)
		getenv            func(string) string
		wantSystemConfig  string
		wantSystemLibexec string
		wantUserLibexec   string
		wantUserConfig    string
		wantUserCache     string
	}{
		{
			name: "windows_test",
			os:   "windows",
			userConfigDir: func() (string, error) {
				return "C:\\User\\exampleuser\\AppData\\Roaming", nil
			},
			userCacheDir: func() (string, error) {
				return "C:\\User\\exampleuser\\AppData\\Local", nil
			},
			getenv: func(s string) string {
				return map[string]string{
					"ProgramFiles": "C:\\Program Files",
					"ProgramData":  "C:\\ProgramData",
				}[s]
			},
			wantSystemConfig:  "C:\\ProgramData\\notation",
			wantSystemLibexec: "C:\\Program Files\\notation",
			wantUserConfig:    "C:\\User\\exampleuser\\AppData\\Roaming\\notation",
			wantUserLibexec:   "C:\\User\\exampleuser\\AppData\\Roaming\\notation",
			wantUserCache:     "C:\\User\\exampleuser\\AppData\\Local\\notation",
		},
		{
			name: "linux_test",
			os:   "linux",
			userConfigDir: func() (string, error) {
				return "/home/exampleuser/.config", nil
			},
			userCacheDir: func() (string, error) {
				return "/home/exampleuser/.cache", nil
			},
			getenv: func(s string) string {
				return map[string]string{}[s]
			},
			wantSystemConfig:  "/etc/notation",
			wantSystemLibexec: "/usr/libexec/notation",
			wantUserConfig:    "/home/exampleuser/.config/notation",
			wantUserLibexec:   "/home/exampleuser/.config/notation",
			wantUserCache:     "/home/exampleuser/.cache/notation",
		},
		{
			name: "darwin_test",
			os:   "darwin",
			userConfigDir: func() (string, error) {
				return "/Users/exampleuser/Library/Application Support", nil
			},
			userCacheDir: func() (string, error) {
				return "/Users/exampleuser/Library/Caches", nil
			},
			getenv: func(s string) string {
				return map[string]string{}[s]
			},
			wantSystemConfig:  "/Library/Application Support/notation",
			wantSystemLibexec: "/usr/local/lib/notation",
			wantUserConfig:    "/Users/exampleuser/Library/Application Support/notation",
			wantUserLibexec:   "/Users/exampleuser/Library/Application Support/notation",
			wantUserCache:     "/Users/exampleuser/Library/Caches/notation",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			goos = tt.os
			userConfigDir = tt.userConfigDir
			userCacheDir = tt.userCacheDir
			getenv = tt.getenv
			loadPath()
			assertPathEqual(t, tt.wantSystemConfig, SystemConfig, "systemConfig error.")
			assertPathEqual(t, tt.wantSystemLibexec, SystemLibexec, "systemLibexec error.")
			assertPathEqual(t, tt.wantUserConfig, UserConfig, "userConfig error.")
			assertPathEqual(t, tt.wantUserLibexec, UserLibexec, "userLibexec")
			assertPathEqual(t, tt.wantUserCache, UserCache, "userCache error.")
		})
	}
}

func assertPathEqual(t *testing.T, want, value, errorMessage string) {
	// replace directory separator on different platform
	want = strings.ReplaceAll(want, "\\", "/")
	value = strings.ReplaceAll(value, "\\", "/")
	if want != value {
		t.Fatalf("%s want = `%v` value = `%v`", errorMessage, want, value)
	}
}

func TestLoadPathError(t *testing.T) {
	tests := []struct {
		name              string
		os                string
		userConfigDir     func() (string, error)
		userCacheDir      func() (string, error)
		getenv            func(string) string
		wantSystemConfig  string
		wantSystemLibexec string
		wantUserLibexec   string
		wantUserConfig    string
		wantUserCache     string
	}{
		{
			name: "windows_panic",
			os:   "windows",
			getenv: func(s string) string {
				return ""
			},
		},
		{
			name: "linux_panic",
			os:   "linux",
			userConfigDir: func() (string, error) {
				return "", errors.New("error")
			},
		},
		{
			name: "linux_panic2",
			os:   "linux",
			userConfigDir: func() (string, error) {
				return "", errors.New("error")
			},
			userCacheDir: func() (string, error) {
				return "", errors.New("error")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			goos = tt.os
			userConfigDir = tt.userConfigDir
			userCacheDir = tt.userCacheDir
			getenv = tt.getenv
			defer func() {
				if r := recover(); r == nil {
					t.Fatal("error")
				}
			}()
			loadPath()
		})
	}
}
