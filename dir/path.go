package dir

import (
	"github.com/opencontainers/go-digest"
)

const (
	// SignatureExtension defines the extension of the signature files
	SignatureExtension = ".sig"
)

// PathIFace is a notation path interface
type PathIFace interface {
	Config() (string, error)
	Localkey(keyName string) (string, error)
	SigningKeyConfig() (string, error)
	TrustPolicy() (string, error)
	X509TrustStore(prefix, storeName string) (string, error)
	CachedSignature(manifestDigest, blobDigest digest.Digest) (string, error)
}

// PathManager contains the union directory file system and methods
// to access paths of notation
type PathManager struct {
	ConfigFS  UnionDirFS
	CacheFS   UnionDirFS
	LibexecFS UnionDirFS
}

// Config returns the path of config.json
func (p *PathManager) Config() (string, error) {
	return p.ConfigFS.GetPath("config.json")
}

// LocalKey returns path of the local private keys or certificate
// in the localkeys directory
func (p *PathManager) Localkey(keyName string) (string, error) {
	return p.ConfigFS.GetPath("localkeys", keyName)
}

// SigningKeyConfig return the path of signingkeys.json files
func (p *PathManager) SigningKeyConfig() (string, error) {
	return p.ConfigFS.GetPath("signingkeys.json")
}

// TrustPolicy returns the path of trustpolicy.json file
func (p *PathManager) TrustPolicy() (string, error) {
	return p.ConfigFS.GetPath("trustpolicy.json")
}

// X509TrustStore returns the path of x509 trust store certificate
func (p *PathManager) X509TrustStore(prefix, namedStore string) (string, error) {
	return p.ConfigFS.GetPath("truststore", "x509", prefix, namedStore)
}

// CachedSignature returns the cached signature file path
func (p *PathManager) CachedSignature(manifestDigest, signatureDigest digest.Digest) (string, error) {
	return p.CacheFS.GetPath(
		"signatures",
		manifestDigest.Algorithm().String(),
		manifestDigest.Encoded(),
		signatureDigest.Algorithm().String(),
		signatureDigest.Encoded()+SignatureExtension,
	)
}

// CachedSignatureRoot returns the cached signature root path
func (p *PathManager) CachedSignatureRoot(manifestDigest digest.Digest) (string, error) {
	return p.CacheFS.GetPath(
		"signatures",
		manifestDigest.Algorithm().String(),
		manifestDigest.Encoded(),
	)
}
