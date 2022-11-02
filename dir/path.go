package dir

import (
	"os"
	"path"
	"path/filepath"
)

var (
	SystemConfigDir  string // Absolute path of system level {NOTATION_CONFIG}
	SystemLibexecDir string // Absolute path of system level {NOTATION_LIBEXEC}
	UserConfigDir    string // Absolute path of user level {NOTATION_CONFIG}
	UserLibexecDir   string // Absolute path of user level {NOTATION_LIBEXEC}
)

// The relative path to {NOTATION_CONFIG}
const (
	// notation is the directory name for notation configurations.
	notation = "notation"
	// PathConfigFile is the config.json file relative path.
	PathConfigFile = "config.json"
	// PathSigningKeys is the signingkeys file relative path.
	PathSigningKeys = "signingkeys.json"
	// PathTrustPolicy is the trust policy file relative path.
	PathTrustPolicy = "trustpolicy.json"
	// LocalKeysDir is the directory name for local key relative path.
	LocalKeysDir = "localkeys"
	// LocalCertificateExtension defines the extension of the certificate files.
	LocalCertificateExtension = ".crt"
	// LocalKeyExtension defines the extension of the key files.
	LocalKeyExtension = ".key"
	// TrustStoreDir is the directory name of trust store.
	TrustStoreDir = "truststore"
)

var userConfigDir = os.UserCacheDir

func init() {
	loadPath()
}

// loadPath function defines the directory for
// NotationLibexec, NotationConfig
func loadPath() {
	// set user config
	userDir, err := userConfigDir()
	if err != nil {
		panic(err)
	}
	UserConfigDir = filepath.Join(userDir, notation)

	// set user libexec
	UserLibexecDir = UserConfigDir
}

// LocalKeyPath returns the local key and local cert relative paths.
func LocalKeyPath(name string) (keyPath, certPath string) {
	basePath := path.Join(LocalKeysDir, name)
	return basePath + LocalKeyExtension, basePath + LocalCertificateExtension
}

// X509TrustStoreDir returns the trust store relative path.
//
// items includes named-store and cert-file names.
// the directory follows the pattern of
// {NOTATION_CONFIG}/truststore/x509/{named-store}/{cert-file}
func X509TrustStoreDir(items ...string) string {
	pathItems := []string{TrustStoreDir, "x509"}
	pathItems = append(pathItems, items...)
	return path.Join(pathItems...)
}
