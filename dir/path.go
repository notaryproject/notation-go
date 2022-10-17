package dir

import (
	"errors"
	"io/fs"
	"path/filepath"

	"github.com/opencontainers/go-digest"
)

const (
	// ConfigFile is the name of config file.
	ConfigFile = "config.json"

	// LocalCertificateExtension defines the extension of the certificate files.
	LocalCertificateExtension = ".crt"

	// LocalKeyExtension defines the extension of the key files.
	LocalKeyExtension = ".key"

	// LocalKeysDir is the directory name for local key store.
	LocalKeysDir = "localkeys"

	// SignatureExtension defines the extension of the signature files.
	SignatureExtension = ".sig"

	// SignatureStoreDirName is the name of the signature store directory.
	SignatureStoreDirName = "signatures"

	// SigningKeysFile is the file name of signing key info.
	SigningKeysFile = "signingkeys.json"

	// TrustPolicyFile is the file name of trust policy info.
	TrustPolicyFile = "trustpolicy.json"

	// TrustStoreDir is the directory name of trust store.
	TrustStoreDir = "truststore"
)

// DirLevel defines the directory level.
type DirLevel int

const (
	// UnionLevel is the label to specify the directory to union user and
	// system level while user level has higher priority than system level.
	// [directory spec]: https://github.com/notaryproject/notation/blob/main/specs/directory.md#category
	UnionLevel DirLevel = iota

	// SystemLevel is the label to specify write directory to system level.
	SystemLevel

	// UserLevel is the label to specify write directory to user level.
	UserLevel
)

// PathManager contains the union directory file system and methods
// to access paths of notation.
type PathManager struct {
	ConfigFS  UnionDirFS
	CacheFS   UnionDirFS
	LibexecFS UnionDirFS
}

func checkError(err error) {
	// if path does not exist, the path can be used to create file.
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		panic(err)
	}
}

// Config returns the path of config.json based on named directory level.
//
// dirLevel will be overwritten based on security setting.
func (p *PathManager) Config(dirLevel DirLevel) string {
	var (
		path string
		err  error
	)

	// overwrite dirLevel based on security setting
	dirLevel = secureDirLevel(dirLevel)

	switch dirLevel {
	case UnionLevel:
		path, err = p.ConfigFS.GetPath(ConfigFile)
		checkError(err)
	case SystemLevel:
		path = filepath.Join(SystemConfig, ConfigFile)
	case UserLevel:
		path = filepath.Join(UserConfig, ConfigFile)
	}

	return path
}

// LocalKey returns the user level path of the local private key and
// it's certificate in the localkeys directory.
func (p *PathManager) Localkey(name string) (keyPath, certPath string) {
	keyPath = filepath.Join(UserConfig, LocalKeysDir, name+LocalKeyExtension)
	certPath = filepath.Join(UserConfig, LocalKeysDir, name+LocalCertificateExtension)
	return
}

// SigningKeyConfig returns the writable user level path of signingkeys.json
// files.
func (p *PathManager) SigningKeyConfig() string {
	return filepath.Join(UserConfig, SigningKeysFile)
}

// TrustPolicy returns the path of trustpolicy.json file based on named
// directory level.
//
// dirLevel will be overwritten based on security setting.
func (p *PathManager) TrustPolicy(dirLevel DirLevel) string {
	var (
		path string
		err  error
	)

	// overwrite dirLevel based on security setting
	dirLevel = secureDirLevel(dirLevel)

	switch dirLevel {
	case UnionLevel:
		path, err = p.ConfigFS.GetPath(TrustPolicyFile)
		checkError(err)
	case SystemLevel:
		path = filepath.Join(SystemConfig, TrustPolicyFile)
	case UserLevel:
		path = filepath.Join(UserConfig, TrustPolicyFile)
	}

	return path
}

// TrustStore returns the path of x509 trust store certificate
// based on named directory level.
//
// dirLevel will be overwritten based on security setting.
// elements are the sub-directories or file name under `truststore` directory.
func (p *PathManager) TrustStore(dirLevel DirLevel, elements ...string) string {
	var (
		path string
		err  error
	)
	// overwrite dirLevel based on security setting
	dirLevel = secureDirLevel(dirLevel)

	pathElements := append([]string{TrustStoreDir, "x509"}, elements...)

	switch dirLevel {
	case UnionLevel:
		path, err = p.ConfigFS.GetPath(pathElements...)
		checkError(err)
	case SystemLevel:
		path = filepath.Join(append([]string{SystemConfig}, pathElements...)...)
	case UserLevel:
		path = filepath.Join(append([]string{UserConfig}, pathElements...)...)
	}

	return path
}

// CachedSignature returns the cached signature file path.
func (p *PathManager) CachedSignature(manifestDigest, signatureDigest digest.Digest) string {
	path, err := p.CacheFS.GetPath(
		SignatureStoreDirName,
		manifestDigest.Algorithm().String(),
		manifestDigest.Encoded(),
		signatureDigest.Algorithm().String(),
		signatureDigest.Encoded()+SignatureExtension,
	)
	checkError(err)
	return path
}

// CachedSignatureRoot returns the cached signature root path.
func (p *PathManager) CachedSignatureRoot(manifestDigest digest.Digest) string {
	path, err := p.CacheFS.GetPath(
		SignatureStoreDirName,
		manifestDigest.Algorithm().String(),
		manifestDigest.Encoded(),
	)
	checkError(err)
	return path
}

// CachedSignatureStoreDirPath returns the cached signing keys directory.
func (p *PathManager) CachedSignatureStoreDirPath() string {
	path, err := p.CacheFS.GetPath(SignatureStoreDirName)
	checkError(err)
	return path
}

// secureDirLevel checks the security requirement based on `Harden` field in
// system level config.json and returns the directory level satisfying the
// security requirement.
func secureDirLevel(dirLevel DirLevel) DirLevel {
	// if Harden is true, only use system directory
	if harden == true {
		return SystemLevel
	}
	return dirLevel
}
