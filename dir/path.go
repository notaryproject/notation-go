package dir

import (
	"errors"
	"io/fs"
)

const (
	// ConfigFile is the name of config file
	ConfigFile = "config.json"

	// LocalCertificateExtension defines the extension of the certificate files
	LocalCertificateExtension = ".crt"

	// LocalKeyExtension defines the extension of the key files
	LocalKeyExtension = ".key"

	// LocalKeysDir is the directory name for local key store
	LocalKeysDir = "localkeys"

	// SignatureExtension defines the extension of the signature files
	SignatureExtension = ".sig"

	// SignatureStoreDirName is the name of the signature store directory
	SignatureStoreDirName = "signatures"

	// SigningKeysFile is the file name of signing key info
	SigningKeysFile = "signingkeys.json"

	// TrustPolicyFile is the file name of trust policy info
	TrustPolicyFile = "trustpolicy.json"

	// TrustStoreDir is the directory name of trust store
	TrustStoreDir = "truststore"
)

// WriteLevel defines the write directory level supporting UserLevel or SystemLevel.
type WriteLevel int

const (
	// SystemLevel is the label to specify write directory to system level
	SystemLevel WriteLevel = 0
	// UserLevel is the label to specify write directory to user level
	UserLevel WriteLevel = 1
)

// PathManager contains the union directory file system and methods
// to access paths of notation
type PathManager struct {
	ConfigFS  UnionDirFS
	LibexecFS UnionDirFS

	UserConfigFS   UnionDirFS
	SystemConfigFS UnionDirFS

	UserLibexecFS   UnionDirFS
	SystemLibexecFS UnionDirFS
}

func checkError(err error) {
	// if path does not exist, the path can be used to create file
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		panic(err)
	}
}

// Config returns the ready-only path of config.json
func (p *PathManager) Config() string {
	path, err := p.ConfigFS.GetPath(ConfigFile)
	checkError(err)
	return path
}

// ConfigForWrite returns the writable path of config.json
func (p *PathManager) ConfigForWrite(writeLevel WriteLevel) string {
	return getPathForWrite(writeLevel, p.UserConfigFS, p.SystemConfigFS, ConfigFile)
}

// LocalKey returns the user level path of the local private key and it's certificate
// in the localkeys directory
func (p *PathManager) Localkey(name string) (keyPath, certPath string) {
	keyPath, err := p.UserConfigFS.GetPath(LocalKeysDir, name+LocalKeyExtension)
	checkError(err)
	certPath, err = p.UserConfigFS.GetPath(LocalKeysDir, name+LocalCertificateExtension)
	checkError(err)
	return keyPath, certPath
}

// SigningKeyConfig returns the writable user level path of signingkeys.json files
func (p *PathManager) SigningKeyConfig() string {
	path, err := p.UserConfigFS.GetPath(SigningKeysFile)
	checkError(err)
	return path
}

// TrustPolicy returns the ready-only path of trustpolicy.json file
func (p *PathManager) TrustPolicy() string {
	path, err := p.ConfigFS.GetPath(TrustPolicyFile)
	checkError(err)
	return path
}

// TrustPolicyForWrite returns the writable path of trustpolicy.json file
func (p *PathManager) TrustPolicyForWrite(writeLevel WriteLevel) string {
	return getPathForWrite(writeLevel, p.UserConfigFS, p.SystemConfigFS, TrustPolicyFile)
}

// X509TrustStore returns the read-only path of x509 trust store certificate
func (p *PathManager) X509TrustStore(prefix, namedStore string) string {
	path, err := p.ConfigFS.GetPath(TrustStoreDir, "x509", prefix, namedStore)
	checkError(err)
	return path
}

// X509TrustStoreForWrite returns the writable path of x509 trust store certificate
func (p *PathManager) X509TrustStoreForWrite(writeLevel WriteLevel, prefix, namedStore string) string {
	return getPathForWrite(writeLevel, p.UserConfigFS, p.SystemConfigFS,
		TrustStoreDir, "x509", prefix, namedStore)
}

func getPathForWrite(writeLevel WriteLevel, user UnionDirFS, system UnionDirFS, items ...string) string {
	var (
		path string
		err  error
	)
	if writeLevel == SystemLevel {
		path, err = system.GetPath(items...)
	} else {
		path, err = user.GetPath(items...)
	}

	checkError(err)
	return path
}
