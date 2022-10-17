package dir

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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
			got := config.TrustStore(UnionLevel, tt.args.prefix, tt.args.namedStore)
			assertPathEqual(t, tt.want, got, "X509TrustStoreCerts path error.")
		})
	}
}

func TestConfigForWrite(t *testing.T) {
	config := PathManager{}
	UserConfig = "/user/exampleuser/.config/notation/"
	SystemConfig = "/etc/notation/"

	type args struct {
		WriteLevel DirLevel
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
			got := config.Config(tt.args.WriteLevel)
			assertPathEqual(t, tt.want, got, "config path for write error.")
		})
	}
}

func TestTrustStoreForWrite(t *testing.T) {
	config := PathManager{}
	UserConfig = "/user/exampleuser/.config/notation/"
	SystemConfig = "/etc/notation/"
	type args struct {
		WriteLevel DirLevel
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
			got := config.TrustStore(tt.args.WriteLevel, "ca", "jj")
			assertPathEqual(t, tt.want, got, "config path for write error.")
		})
	}
}

func TestTrustPolicyForWrite(t *testing.T) {
	config := PathManager{}
	UserConfig = "/user/exampleuser/.config/notation/"
	SystemConfig = "/etc/notation/"
	type args struct {
		WriteLevel DirLevel
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
			got := config.TrustPolicy(tt.args.WriteLevel)
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
	configPath := path.Config(UnionLevel)
	if configPath != "/home/exampleuser/.config/notation/"+ConfigFile {
		t.Fatal("get Config() failed.")
	}
}

func TestPathManager_LocalKey(t *testing.T) {
	path := &PathManager{}
	UserConfig = "/home/exampleuser/.config/notation/"
	keyPath, certPath := path.Localkey("key1")
	if keyPath != "/home/exampleuser/.config/notation/localkeys/key1"+LocalKeyExtension {
		t.Fatal("get Localkey() failed.")
	}
	if certPath != "/home/exampleuser/.config/notation/localkeys/key1"+LocalCertificateExtension {
		t.Fatal("get Localkey() failed.")
	}
}

func TestPathManager_SigningKeyConfig(t *testing.T) {
	path := &PathManager{}
	UserConfig = "/home/exampleuser/.config/notation/"
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
	policyPath := path.TrustPolicy(UnionLevel)
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
	storePath := path.TrustStore(UnionLevel, "ca", "store")
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

func TestSecureDirLevel(t *testing.T) {
	// backup and restore system config path
	systemConfigBak := SystemConfig
	t.Cleanup(func() {
		SystemConfig = systemConfigBak
	})

	// generate temp config
	SystemConfig = t.TempDir()

	setHarden := func(harden bool, fileMode fs.FileMode) {
		configPath := filepath.Join(SystemConfig, "config.json")
		os.Remove(configPath)
		f, err := os.OpenFile(configPath, os.O_CREATE|os.O_RDWR, fileMode)
		if err != nil {
			t.Fatal(err)
		}
		f.WriteString(fmt.Sprintf(`{"Harden": %v}`, harden))
		f.Close()
		loadSettings()
	}

	t.Run("no config.json", func(t *testing.T) {
		dirLevel := secureDirLevel(UserLevel)
		if dirLevel != UserLevel {
			t.Fatalf("want dirLevel: %v, got dirLevel: %v", UserLevel, dirLevel)
		}
	})

	t.Run("harden is false", func(t *testing.T) {
		setHarden(false, 0644)
		dirLevel := secureDirLevel(UserLevel)
		if dirLevel != UserLevel {
			t.Fatalf("want dirLevel: %v, got dirLevel: %v", UserLevel, dirLevel)
		}
	})

	t.Run("harden is true", func(t *testing.T) {
		setHarden(true, 0644)
		dirLevel := secureDirLevel(UserLevel)
		if dirLevel != SystemLevel {
			t.Fatalf("want dirLevel: %v, got dirLevel: %v", SystemLevel, dirLevel)
		}
	})

	t.Run("config permission error", func(t *testing.T) {
		defer func() {
			if d := recover(); d != nil {
				return
			}
		}()
		setHarden(true, 0000)
		dirLevel := secureDirLevel(UserLevel)
		if dirLevel != SystemLevel {
			t.Fatalf("want dirLevel: %v, got dirLevel: %v", SystemLevel, dirLevel)
		}
		t.Fatal("should panic")
	})
}
