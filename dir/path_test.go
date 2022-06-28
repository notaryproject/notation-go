package dir

import (
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/opencontainers/go-digest"
)

func TestCachedSignature(t *testing.T) {
	cache := PathManager{CacheFS: UnionDirFS{
		Dirs: []RootedFS{
			{
				FS:   fstest.MapFS{"signatures/sha256/x1/sha256/x2": &fstest.MapFile{}},
				Root: "/user/exampleuser/.cache/notation",
			},
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
			want:    "/user/exampleuser/.cache/notation/signatures/sha256/x1/sha256/x2",
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
	cache := PathManager{CacheFS: UnionDirFS{
		Dirs: []RootedFS{
			{
				FS:   fstest.MapFS{"signature/sha256/x1/sha256/x2": &fstest.MapFile{}},
				Root: "/user/exampleuser/.cache/notation",
			},
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
			_, err := cache.CachedSignature(tt.args.manifestDigest, tt.args.blobDigest)
			if (err != nil) != tt.wantErr {
				t.Errorf("CachedSignature() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestX509TrustStoreCerts(t *testing.T) {
	config := PathManager{ConfigFS: UnionDirFS{
		Dirs: []RootedFS{
			{
				FS:   fstest.MapFS{"truststore/x509/ca/store1": &fstest.MapFile{Mode: fs.ModeDir}},
				Root: "/user/exampleuser/.config/notation",
			},
			{
				FS:   fstest.MapFS{"truststore/x509/ca/store1": &fstest.MapFile{Mode: fs.ModeDir}},
				Root: "/etc/notation",
			},
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
