package dir

import (
	"errors"
	"fmt"
	"strings"

	"github.com/opencontainers/go-digest"
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

// PathManager contains the union directory file system and methods to access paths of notation
type PathManager struct {
	ConfigFS  UnionDirFS
	CacheFS   UnionDirFS
	LibexecFS UnionDirFS
}

// Config returns the path of config.json
func (p PathManager) Config() (string, error) {
	return p.ConfigFS.GetPath("config.json")
}

// LocalKeys returns path of the local private keys or certificate in the localkeys directory
func (p PathManager) Localkey(keyName string) (string, error) {
	return p.ConfigFS.GetPath("localkeys", keyName)
}

// SigningKeys return the path of signingkeys.json files
func (p PathManager) SigningKeyConfig() (string, error) {
	return p.ConfigFS.GetPath("signingkeys.json")
}

// TrustPolicy returns the path of trustpolicy.json file
func (p PathManager) TrustPolicy() (string, error) {
	return p.ConfigFS.GetPath("trustpolicy.json")
}

// TrustStore returns the path of x509 trust store certificate
func (p PathManager) X509TrustStore(prefix, namedStore string) (string, error) {
	return p.ConfigFS.GetPath("truststore", "x509", prefix, namedStore)
}

// CachedSignature returns the cached signature file path
func (p PathManager) CachedSignature(manifestDigest, blobDigest digest.Digest) (string, error) {
	manifestAlgorithmAndDigest := strings.Split(string(manifestDigest), ":")
	if len(manifestAlgorithmAndDigest) != 2 {
		return "", errors.New(fmt.Sprintf("digest %s is not valid.", manifestDigest))
	}
	blobAlgorithmAndDigest := strings.Split(string(blobDigest), ":")
	if len(blobAlgorithmAndDigest) != 2 {
		return "", errors.New(fmt.Sprintf("digest %s is not valid.", blobDigest))
	}
	elem := []string{"signatures"}
	elem = append(elem, manifestAlgorithmAndDigest...)
	elem = append(elem, blobAlgorithmAndDigest...)
	return p.CacheFS.GetPath(elem...)
}
