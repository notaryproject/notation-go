package dir

import (
	"errors"
	"io/fs"

	"github.com/opencontainers/go-digest"
)

const (
	// SignatureExtension defines the extension of the signature files
	SignatureExtension = ".sig"
	// ConfigFile is the name of config file
	ConfigFile = "config.json"
	// LocalKeysDir is the directory name for local key store
	LocalKeysDir = "localkeys"
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

func errorHandler(path string, err error) string {
	// if path does not exist, return path for creating file.
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		panic(err)
	}
	return path
}

// Config returns the path of config.json
func (p *PathManager) Config() string {
	return errorHandler(p.ConfigFS.GetPath(ConfigFile))
}

// LocalKey returns path of the local private keys or certificate
// in the localkeys directory
func (p *PathManager) Localkey(keyName string) string {
	return errorHandler(p.UserConfigFS.GetPath(LocalKeysDir, keyName))
}

// SigningKeyConfig return the path of signingkeys.json files
func (p *PathManager) SigningKeyConfig() string {
	return errorHandler(p.UserConfigFS.GetPath(SigningKeysFile))
}

// TrustPolicy returns the path of trustpolicy.json file
func (p *PathManager) TrustPolicy() string {
	return errorHandler(p.ConfigFS.GetPath(TrustPolicyFile))
}

// X509TrustStore returns the path of x509 trust store certificate
func (p *PathManager) X509TrustStore(prefix, namedStore string) string {
	return errorHandler(p.ConfigFS.GetPath(TrustStoreDir, "x509", prefix, namedStore))
}

// CachedSignature returns the cached signature file path
func (p *PathManager) CachedSignature(manifestDigest, signatureDigest digest.Digest) string {
	return errorHandler(p.CacheFS.GetPath(
		"signatures",
		manifestDigest.Algorithm().String(),
		manifestDigest.Encoded(),
		signatureDigest.Algorithm().String(),
		signatureDigest.Encoded()+SignatureExtension,
	))
}

// CachedSignatureRoot returns the cached signature root path
func (p *PathManager) CachedSignatureRoot(manifestDigest digest.Digest) string {
	return errorHandler(p.CacheFS.GetPath(
		"signatures",
		manifestDigest.Algorithm().String(),
		manifestDigest.Encoded(),
	))
}
