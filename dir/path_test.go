package dir

import (
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/opencontainers/go-digest"
)

func TestCachedSignature(t *testing.T) {
	cache := PathManager{CacheFS: unionDirFS{
		Dirs: []RootedFS{
			NewRootedFS(
				"/user/exampleuser/.cache/notation",
				fstest.MapFS{"signatures/sha256/x1/sha256/x2.sig": &fstest.MapFile{}},
			),
		},
	}}
	type args struct {
		manifestDigest digest.Digest
		blobDigest     digest.Digest
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name:    "test get cache",
			args:    args{"sha256:x1", "sha256:x2"},
			want:    "/user/exampleuser/.cache/notation/signatures/sha256/x1/sha256/x2.sig",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := cache.CachedSignature(tt.args.manifestDigest, tt.args.blobDigest)
			if (err != nil) != tt.wantErr {
				t.Errorf("CachedSignature() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assertPathEqual(t, tt.want, got, "get cache path error")
		})
	}
}

func TestCachedSignatureFailed(t *testing.T) {
	cache := PathManager{CacheFS: unionDirFS{
		Dirs: []RootedFS{
			NewRootedFS(
				"/user/exampleuser/.cache/notation",
				fstest.MapFS{"signature/sha256/x1/sha256/x2": &fstest.MapFile{}},
			),
		},
	}}
	type args struct {
		manifestDigest digest.Digest
		blobDigest     digest.Digest
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name:    "test get cache",
			args:    args{"sha256x1", "sha256:x2"},
			want:    "/user/exampleuser/.cache/notation/signatures/sha256/x1/sha256/x2",
			wantErr: true,
		},
		{
			name:    "test get cache",
			args:    args{"sha256:x1", "sha256x2"},
			want:    "/user/exampleuser/.cache/notation/signatures/sha256/x1/sha256/x2",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if d := recover(); d == nil {
					t.Fatal("should panic.")
				}
			}()
			cache.CachedSignature(tt.args.manifestDigest, tt.args.blobDigest)
		})
	}
}

func TestX509TrustStoreCerts(t *testing.T) {
	config := PathManager{ConfigFS: unionDirFS{
		Dirs: []RootedFS{
			NewRootedFS(
				"/user/exampleuser/.config/notation",
				fstest.MapFS{"truststore/x509/ca/store1": &fstest.MapFile{Mode: fs.ModeDir}},
			),
			NewRootedFS(
				"/etc/notation",
				fstest.MapFS{"truststore/x509/ca/store1": &fstest.MapFile{Mode: fs.ModeDir}},
			),
		},
	}}
	type args struct {
		prefix     string
		namedStore string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name:    "test named store1",
			args:    args{"ca", "store1"},
			want:    "/user/exampleuser/.config/notation/truststore/x509/ca/store1",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := config.X509TrustStore(tt.args.prefix, tt.args.namedStore)
			if (err != nil) != tt.wantErr {
				t.Errorf("X509TrustStoreCerts() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assertPathEqual(t, tt.want, got, "X509TrustStoreCerts path error.")
		})
	}
}
