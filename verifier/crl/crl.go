// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package crl provides functionalities for crl revocation check.
package crl

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	corecrl "github.com/notaryproject/notation-core-go/revocation/crl"
	"github.com/notaryproject/notation-go/internal/file"
	"github.com/notaryproject/notation-go/log"
)

// FileCache implements corecrl.Cache.
//
// Key: url of the CRL.
//
// Value: corecrl.Bundle.
//
// This cache builds on top of the UNIX file system to leverage the file system's
// atomic operations. The `rename` and `remove` operations will unlink the old
// file but keep the inode and file descriptor for existing processes to access
// the file. The old inode will be dereferenced when all processes close the old
// file descriptor. Additionally, the operations are proven to be atomic on
// UNIX-like platforms, so there is no need to handle file locking.
//
// NOTE: For Windows, the `open`, `rename` and `remove` operations need file
// locking to ensure atomicity. The current implementation does not handle
// file locking, so the concurrent write from multiple processes may be failed.
// Please do not use this cache in a multi-process environment on Windows.
type FileCache struct {
	// root is the root directory of the cache
	root string
}

// fileCacheContent is the actual content saved in a FileCache
type fileCacheContent struct {
	// BaseCRL is the ASN.1 encoded base CRL
	BaseCRL []byte `json:"baseCRL"`

	// DeltaCRL is the ASN.1 encoded delta CRL
	DeltaCRL []byte `json:"deltaCRL,omitempty"`
}

// NewFileCache creates a FileCache with root as the root directory
//
// An example for root is `dir.CacheFS().SysPath(dir.PathCRLCache)`
func NewFileCache(root string) (*FileCache, error) {
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, fmt.Errorf("failed to create crl file cache: %w", err)
	}
	return &FileCache{
		root: root,
	}, nil
}

// Get retrieves CRL bundle from c given url as key. If the key does not exist
// or the content has expired, corecrl.ErrCacheMiss is returned.
func (c *FileCache) Get(ctx context.Context, url string) (*corecrl.Bundle, error) {
	logger := log.GetLogger(ctx)
	logger.Debugf("Retrieving crl bundle from file cache with key %q ...", url)

	// get content from file cache
	contentBytes, err := os.ReadFile(filepath.Join(c.root, c.fileName(url)))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			logger.Debugf("CRL file cache miss. Key %q does not exist", url)
			return nil, corecrl.ErrCacheMiss
		}
		return nil, fmt.Errorf("failed to get crl bundle from file cache with key %q: %w", url, err)
	}

	// decode content to crl Bundle
	var content fileCacheContent
	if err := json.Unmarshal(contentBytes, &content); err != nil {
		return nil, fmt.Errorf("failed to decode file retrieved from file cache: %w", err)
	}
	var bundle corecrl.Bundle
	bundle.BaseCRL, err = x509.ParseRevocationList(content.BaseCRL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base CRL of file retrieved from file cache: %w", err)
	}
	if content.DeltaCRL != nil {
		bundle.DeltaCRL, err = x509.ParseRevocationList(content.DeltaCRL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse delta CRL of file retrieved from file cache: %w", err)
		}
	}

	// check expiry
	if err := checkExpiry(ctx, bundle.BaseCRL.NextUpdate); err != nil {
		return nil, err
	}
	if bundle.DeltaCRL != nil {
		if err := checkExpiry(ctx, bundle.DeltaCRL.NextUpdate); err != nil {
			return nil, err
		}
	}

	return &bundle, nil
}

// Set stores the CRL bundle in c with url as key.
func (c *FileCache) Set(ctx context.Context, url string, bundle *corecrl.Bundle) error {
	logger := log.GetLogger(ctx)
	logger.Debugf("Storing crl bundle to file cache with key %q ...", url)

	if bundle == nil {
		return errors.New("failed to store crl bundle in file cache: bundle cannot be nil")
	}
	if bundle.BaseCRL == nil {
		return errors.New("failed to store crl bundle in file cache: bundle BaseCRL cannot be nil")
	}

	// actual content to be saved in the cache
	content := fileCacheContent{
		BaseCRL: bundle.BaseCRL.Raw,
	}
	if bundle.DeltaCRL != nil {
		content.DeltaCRL = bundle.DeltaCRL.Raw
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return fmt.Errorf("failed to store crl bundle in file cache: %w", err)
	}
	if err := file.WriteFile(c.root, filepath.Join(c.root, c.fileName(url)), contentBytes); err != nil {
		return fmt.Errorf("failed to store crl bundle in file cache: %w", err)
	}
	return nil
}

// fileName returns the filename of the content stored in c
func (c *FileCache) fileName(url string) string {
	hash := sha256.Sum256([]byte(url))
	return hex.EncodeToString(hash[:])
}

// checkExpiry returns nil when nextUpdate is bounded before current time
func checkExpiry(ctx context.Context, nextUpdate time.Time) error {
	logger := log.GetLogger(ctx)

	if nextUpdate.IsZero() {
		return errors.New("crl bundle retrieved from file cache does not contain valid NextUpdate")
	}
	if time.Now().After(nextUpdate) {
		logger.Debugf("CRL bundle retrieved from file cache has expired at %s", nextUpdate)
		return corecrl.ErrCacheMiss
	}
	return nil
}
