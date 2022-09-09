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
		name string
		args args
		want string
	}{
		{
			name: "test get cache",
			args: args{"sha256:x1", "sha256:x2"},
			want: "/user/exampleuser/.cache/notation/signatures/sha256/x1/sha256/x2.sig",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cache.CachedSignature(tt.args.manifestDigest, tt.args.blobDigest)
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
		name string
		args args
		want string
	}{
		{
			name: "test get cache",
			args: args{"sha256x1", "sha256:x2"},
			want: "/user/exampleuser/.cache/notation/signatures/sha256/x1/sha256/x2",
		},
		{
			name: "test get cache",
			args: args{"sha256:x1", "sha256x2"},
			want: "/user/exampleuser/.cache/notation/signatures/sha256/x1/sha256/x2",
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
			got := config.X509TrustStore(tt.args.prefix, tt.args.namedStore)
			assertPathEqual(t, tt.want, got, "X509TrustStoreCerts path error.")
		})
	}
}

func TestConfigForWrite(t *testing.T) {
	config := PathManager{
		UserConfigFS: unionDirFS{
			Dirs: []RootedFS{
				NewRootedFS(
					"/user/exampleuser/.config/notation",
					fstest.MapFS{},
				),
			},
		},
		SystemConfigFS: unionDirFS{
			Dirs: []RootedFS{
				NewRootedFS(
					"/etc/notation",
					fstest.MapFS{},
				),
			},
		},
	}
	type args struct {
		WriteLevel WriteLevel
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name:    "config path for write in user level",
			args:    args{UserLevel},
			want:    "/user/exampleuser/.config/notation/config.json",
			wantErr: false,
		},
		{
			name:    "config path for write in system level",
			args:    args{SystemLevel},
			want:    "/etc/notation/config.json",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := config.ConfigForWrite(tt.args.WriteLevel)
			assertPathEqual(t, tt.want, got, "config path for write error.")
		})
	}
}

func TestTrustStoreForWrite(t *testing.T) {
	config := PathManager{
		UserConfigFS: unionDirFS{
			Dirs: []RootedFS{
				NewRootedFS(
					"/user/exampleuser/.config/notation",
					fstest.MapFS{},
				),
			},
		},
		SystemConfigFS: unionDirFS{
			Dirs: []RootedFS{
				NewRootedFS(
					"/etc/notation",
					fstest.MapFS{},
				),
			},
		},
	}
	type args struct {
		WriteLevel WriteLevel
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name:    "trust store path for write in user level",
			args:    args{UserLevel},
			want:    "/user/exampleuser/.config/notation/truststore/x509/ca/jj",
			wantErr: false,
		},
		{
			name:    "trust store path for write in system level",
			args:    args{SystemLevel},
			want:    "/etc/notation/truststore/x509/ca/jj",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := config.X509TrustStoreForWrite(tt.args.WriteLevel, "ca", "jj")
			assertPathEqual(t, tt.want, got, "config path for write error.")
		})
	}
}

func TestTrustPolicyForWrite(t *testing.T) {
	config := PathManager{
		UserConfigFS: unionDirFS{
			Dirs: []RootedFS{
				NewRootedFS(
					"/user/exampleuser/.config/notation",
					fstest.MapFS{},
				),
			},
		},
		SystemConfigFS: unionDirFS{
			Dirs: []RootedFS{
				NewRootedFS(
					"/etc/notation",
					fstest.MapFS{},
				),
			},
		},
	}
	type args struct {
		WriteLevel WriteLevel
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name:    "trust policy path for write in user level",
			args:    args{UserLevel},
			want:    "/user/exampleuser/.config/notation/trustpolicy.json",
			wantErr: false,
		},
		{
			name:    "trust policy path for write in system level",
			args:    args{SystemLevel},
			want:    "/etc/notation/trustpolicy.json",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := config.TrustPolicyForWrite(tt.args.WriteLevel)
			assertPathEqual(t, tt.want, got, "config path for write error.")
		})
	}
}

func TestPathManager_Config(t *testing.T) {
	path := &PathManager{
		ConfigFS: NewUnionDirFS(
			NewRootedFS("/home/exampleuser/.config/notation/", nil),
		),
	}
	configPath := path.Config()
	if configPath != "/home/exampleuser/.config/notation/"+ConfigFile {
		t.Fatal("get Config() failed.")
	}
}

func TestPathManager_LocalKey(t *testing.T) {
	path := &PathManager{
		UserConfigFS: NewUnionDirFS(
			NewRootedFS("/home/exampleuser/.config/notation/", nil),
		),
	}
	keyPath, certPath := path.Localkey("key1")
	if keyPath != "/home/exampleuser/.config/notation/localkeys/key1"+LocalKeyExtension {
		t.Fatal("get Localkey() failed.")
	}
	if certPath != "/home/exampleuser/.config/notation/localkeys/key1"+LocalCertificateExtension {
		t.Fatal("get Localkey() failed.")
	}
}

func TestPathManager_SigningKeyConfig(t *testing.T) {
	path := &PathManager{
		UserConfigFS: NewUnionDirFS(
			NewRootedFS("/home/exampleuser/.config/notation/", nil),
		),
	}
	signingKeyPath := path.SigningKeyConfig()
	if signingKeyPath != "/home/exampleuser/.config/notation/"+SigningKeysFile {
		t.Fatal("get SigningKeyConfig() failed.")
	}
}

func TestPathManager_TrustPolicy(t *testing.T) {
	path := &PathManager{
		ConfigFS: NewUnionDirFS(
			NewRootedFS("/home/exampleuser/.config/notation/", nil),
		),
	}
	policyPath := path.TrustPolicy()
	if policyPath != "/home/exampleuser/.config/notation/"+TrustPolicyFile {
		t.Fatal("get TrustPolicy() failed.")
	}
}

func TestPathManager_X509TrustStore(t *testing.T) {
	path := &PathManager{
		ConfigFS: NewUnionDirFS(
			NewRootedFS("/home/exampleuser/.config/notation/", nil),
		),
	}
	storePath := path.X509TrustStore("ca", "store")
	if storePath != "/home/exampleuser/.config/notation/truststore/x509/ca/store" {
		t.Fatal("get X509TrustStore() failed.")
	}
}

func TestPathManager_CachedSignature(t *testing.T) {
	path := &PathManager{
		CacheFS: NewUnionDirFS(
			NewRootedFS("/home/exampleuser/.cache/notation/", nil),
		),
	}
	signaturePath := path.CachedSignature("sha256:x1", "sha256:x2")
	if signaturePath != "/home/exampleuser/.cache/notation/signatures/sha256/x1/sha256/x2.sig" {
		t.Fatal("get CachedSignature() failed.")
	}
}

func TestPathManager_CachedSignatureRoot(t *testing.T) {
	path := &PathManager{
		CacheFS: NewUnionDirFS(
			NewRootedFS("/home/exampleuser/.cache/notation/", nil),
		),
	}
	signaturePath := path.CachedSignatureRoot("sha256:x1")
	if signaturePath != "/home/exampleuser/.cache/notation/signatures/sha256/x1" {
		t.Fatal("get CachedSignatureRoot() failed.")
	}
}

func TestPathManager_CachedSignatureStoreDirPath(t *testing.T) {
	path := &PathManager{
		CacheFS: NewUnionDirFS(
			NewRootedFS("/home/exampleuser/.cache/notation/", nil),
		),
	}
	signatureDirPath := path.CachedSignatureStoreDirPath()
	if signatureDirPath != "/home/exampleuser/.cache/notation/signatures" {
		t.Fatal("get CachedSignatureStoreDir() failed.")
	}
}
