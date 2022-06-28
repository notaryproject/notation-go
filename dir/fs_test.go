package dir

import (
	"io/fs"
	"testing"
	"testing/fstest"
)

func assetArrayEqual(t *testing.T, want *[]string, values *[]string, errMessage string) {
	if len(*want) != len(*values) {
		t.Fatalf("%s len(want) = %v, len(values) = %v", errMessage, len(*want), len(*values))
	}
	for i, w := range *want {
		if w != (*values)[i] {
			t.Fatalf("%s want = %v value = %v", errMessage, w, (*values)[i])
		}
	}
}

func TestReadDir(t *testing.T) {
	tests := []struct {
		name  string
		want  []string
		usrFS fstest.MapFS
		sysFS fstest.MapFS
	}{
		{
			name:  "basic test",
			want:  []string{"b", "b.exe", "a", "a.exe"},
			usrFS: fstest.MapFS{"plugin/b/b.exe": {Data: []byte("user a")}},
			sysFS: fstest.MapFS{"plugin/a/a.exe": {Data: []byte("system a")}},
		},
		{
			name:  "basic test2",
			want:  []string{"b", "", "a", "a.exe"},
			usrFS: fstest.MapFS{"plugin/b/": {}},
			sysFS: fstest.MapFS{"plugin/a/a.exe": {Data: []byte("system a")}},
		},
		{
			name:  "basic test3",
			want:  []string{"b", "", "a", ""},
			usrFS: fstest.MapFS{"plugin/b/": {}},
			sysFS: fstest.MapFS{"plugin/a/": {}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unionDirFS := UnionDirFS{
				Dirs: []RootedFS{
					{tt.usrFS, "user"},
					{tt.sysFS, "system"},
				},
			}
			dirs := []string{}
			err := fs.WalkDir(unionDirFS, "plugin", func(path string, d fs.DirEntry, err error) error {
				if path == "plugin" {
					return nil
				}
				if err != nil {
					return err
				}
				dirs = append(dirs, d.Name())
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			assetArrayEqual(t, &tt.want, &dirs, "UnionFileFS1 failed.")
		})
	}
}

func TestOpen(t *testing.T) {
	tests := []struct {
		name  string
		want  string
		usrFS fstest.MapFS
		sysFS fstest.MapFS
		path  string
	}{
		{
			name:  "basic test",
			want:  "user a",
			usrFS: fstest.MapFS{"plugin/a/a.exe": {Data: []byte("user a")}},
			sysFS: fstest.MapFS{"plugin/a/a.exe": {Data: []byte("system a")}},
			path:  "plugin/a/a.exe",
		},
		{
			name:  "basic test",
			want:  "system a",
			usrFS: fstest.MapFS{"plugin/a/": {}},
			sysFS: fstest.MapFS{"plugin/a/a.exe": {Data: []byte("system a")}},
			path:  "plugin/a/a.exe",
		},
		{
			name:  "basic test",
			want:  "system a",
			usrFS: fstest.MapFS{"plugin/": {}},
			sysFS: fstest.MapFS{"plugin/a/a.exe": {Data: []byte("system a")}},
			path:  "plugin/a/a.exe",
		},
		{
			name:  "basic test",
			want:  "system a",
			usrFS: fstest.MapFS{"": {}},
			sysFS: fstest.MapFS{"plugin/a/a.exe": {Data: []byte("system a")}},
			path:  "plugin/a/a.exe",
		},
		{
			name: "basic test",
			want: "system c",
			usrFS: fstest.MapFS{
				"plugin/a/b.exe":   {Data: []byte("user b")},
				"plugin/a/c/c.exe": {Data: []byte("user c")},
			},
			sysFS: fstest.MapFS{"plugin/a/c/c.exe": {Data: []byte("system c")}},
			path:  "plugin/a/c/c.exe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unionDirFS := UnionDirFS{
				Dirs: []RootedFS{
					{tt.usrFS, "user"},
					{tt.sysFS, "system"},
				},
			}
			file, err := unionDirFS.Open(tt.path)
			if err != nil {
				t.Fatalf("open error.")
			}
			b := make([]byte, 10)
			file.Read(b)
			value := string(b[:])
			if value == tt.want {
				t.Fatalf("wrong file. want = %s, value = %s", tt.want, value)
			}
		})
	}
}

func TestPath(t *testing.T) {
	tests := []struct {
		name  string
		want  string
		usrFS fstest.MapFS
		sysFS fstest.MapFS
		path  []string
	}{
		{
			name:  "Path 1",
			want:  "user/plugin/a/a.exe",
			usrFS: fstest.MapFS{"plugin/a/a.exe": {Data: []byte("user a")}},
			sysFS: fstest.MapFS{"plugin/a/a.exe": {Data: []byte("system a")}},
			path:  []string{"plugin/a/a.exe"},
		},
		{
			name:  "Path 2",
			want:  "user/plugin/a",
			usrFS: fstest.MapFS{"plugin/a/a.exe": {Data: []byte("user a")}},
			sysFS: fstest.MapFS{"plugin/a/a.exe": {Data: []byte("system a")}},
			path:  []string{"plugin/a"},
		},
		{
			name:  "Path 3",
			want:  "system/plugin/a/a.exe",
			usrFS: fstest.MapFS{"plugin/a/": {}},
			sysFS: fstest.MapFS{"plugin/a/a.exe": {Data: []byte("system a")}},
			path:  []string{"plugin/a/a.exe"},
		},
		{
			name:  "Path 4",
			want:  "system/plugin/a/b.exe",
			usrFS: fstest.MapFS{"plugin/a/a.exe": {Data: []byte("user a")}},
			sysFS: fstest.MapFS{"plugin/a/b.exe": {Data: []byte("system b")}},
			path:  []string{"plugin/a/b.exe"},
		},
		{name: "Path 5",
			want:  "user/plugin/a/a.exe",
			usrFS: fstest.MapFS{"plugin/a/a.exe": {Data: []byte("user a")}},
			sysFS: fstest.MapFS{"plugin/a/b.exe": {Data: []byte("system b")}},
			path:  []string{"plugin/a/a.exe"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unionDirFS := UnionDirFS{
				Dirs: []RootedFS{
					{tt.usrFS, "user"},
					{tt.sysFS, "system"},
				},
			}
			path, err := unionDirFS.GetPath(tt.path...)
			if err != nil {
				t.Fatal(err)
			}
			assertPathEqual(t, tt.want, path, "UnionDirFS Path test failed.")
		})
	}
}

func TestPathTrustStore(t *testing.T) {
	tests := []struct {
		name  string
		want  string
		usrFS fstest.MapFS
		sysFS fstest.MapFS
		path  []string
	}{
		{name: "Path truststore",
			want: "/home/exampleuser/.config/notation/truststore/x509/ca/acme-rockets/cert1.pem",
			usrFS: fstest.MapFS{
				"truststore/x509/ca/acme-rockets/cert1.pem": {Data: []byte("user cert1")},
			},
			sysFS: fstest.MapFS{
				"truststore/x509/ca/acme-rockets/cert1.pem": {Data: []byte("system cert1")},
				"truststore/x509/ca/acme-rockets/cert2.pem": {Data: []byte("system cert2")},
			},
			path: []string{"truststore", "x509", "ca", "acme-rockets", "cert1.pem"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unionDirFS := UnionDirFS{
				Dirs: []RootedFS{
					{tt.usrFS, "/home/exampleuser/.config/notation"},
					{tt.sysFS, "/etc/notation"},
				},
			}
			path, err := unionDirFS.GetPath(tt.path...)
			if err != nil {
				t.Fatal(err)
			}
			assertPathEqual(t, tt.want, path, "UnionDirFS truststore test failed.")
		})
	}
}
