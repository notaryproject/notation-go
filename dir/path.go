package dir

import (
	"errors"
	"fmt"
	"io/fs"

	"github.com/opencontainers/go-digest"
)

const (
	// CertificateExtension defines the extension of the certificate files
	CertificateExtension = ".crt"

	// ConfigFile is the name of config file
	ConfigFile = "config.json"

	// KeyExtension defines the extension of the key files
	KeyExtension = ".key"

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

// PathManager contains the union directory file system and methods
// to access paths of notation
type PathManager struct {
	ConfigFS     UnionDirFS
	CacheFS      UnionDirFS
	LibexecFS    UnionDirFS
	UserConfigFS UnionDirFS
}

func checkError(err error) {
	// if path does not exist, the path can be used to create file
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		panic(err)
	}
}

// Config returns the path of config.json
func (p *PathManager) Config() string {
	path, err := p.ConfigFS.GetPath(ConfigFile)
	checkError(err)
	return path
}

// LocalKey returns path of the local private keys or certificate
// in the localkeys directory
//
// extension: support .crt|.key
func (p *PathManager) Localkey(name string, extension string) string {
	if extension != KeyExtension && extension != CertificateExtension {
		panic(fmt.Sprintf("doesn't support the extension `%s`", extension))
	}
	path, err := p.UserConfigFS.GetPath(LocalKeysDir, name+extension)
	checkError(err)
	return path
}

// SigningKeyConfig return the path of signingkeys.json files
func (p *PathManager) SigningKeyConfig() string {
	path, err := p.UserConfigFS.GetPath(SigningKeysFile)
	checkError(err)
	return path
}

// TrustPolicy returns the path of trustpolicy.json file
func (p *PathManager) TrustPolicy() string {
	path, err := p.ConfigFS.GetPath(TrustPolicyFile)
	checkError(err)
	return path
}

// X509TrustStore returns the path of x509 trust store certificate
func (p *PathManager) X509TrustStore(prefix, namedStore string) string {
	path, err := p.ConfigFS.GetPath(TrustStoreDir, "x509", prefix, namedStore)
	checkError(err)
	return path
}

// CachedSignature returns the cached signature file path
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

// CachedSignatureRoot returns the cached signature root path
func (p *PathManager) CachedSignatureRoot(manifestDigest digest.Digest) string {
	path, err := p.CacheFS.GetPath(
		SignatureStoreDirName,
		manifestDigest.Algorithm().String(),
		manifestDigest.Encoded(),
	)
	checkError(err)
	return path
}

// CachedSignatureStoreDirPath returns the cached signing keys directory
func (p *PathManager) CachedSignatureStoreDirPath() string {
	path, err := p.CacheFS.GetPath(SignatureStoreDirName)
	checkError(err)
	return path
}
