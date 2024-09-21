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
	"github.com/notaryproject/notation-go/log"
)

const (
	// tmpFileName is the prefix of the temporary file
	tmpFileName = "notation-*"
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
	// RawBaseCRL is baseCRL.Raw
	RawBaseCRL []byte `json:"rawBaseCRL"`

	// RawDeltaCRL is deltaCRL.Raw
	RawDeltaCRL []byte `json:"rawDeltaCRL,omitempty"`
}

// NewFileCache creates a FileCache with root as the root directory
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

	// get content from file cache
	f, err := os.Open(filepath.Join(c.root, c.fileName(url)))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			logger.Infof("CRL file cache miss. Key %q does not exist", url)
			return nil, corecrl.ErrCacheMiss
		}
		return nil, fmt.Errorf("failed to get crl bundle from file cache with key %q: %w", url, err)
	}
	defer f.Close()

	// decode content to crl Bundle
	var content fileCacheContent
	err = json.NewDecoder(f).Decode(&content)
	if err != nil {
		return nil, fmt.Errorf("failed to decode file retrieved from file cache: %w", err)
	}
	// TODO: add DeltaCRL once notation-core-go supports it. Issue: https://github.com/notaryproject/notation-core-go/issues/228
	baseCRL, err := x509.ParseRevocationList(content.RawBaseCRL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base CRL of file retrieved from file cache: %w", err)
	}
	bundle := corecrl.Bundle{
		BaseCRL: baseCRL,
	}

	// check expiry
	nextUpdate := baseCRL.NextUpdate
	if nextUpdate.IsZero() {
		return nil, errors.New("crl bundle retrieved from file cache does not contain BaseCRL NextUpdate")
	}
	if time.Now().After(nextUpdate) {
		// content in file cache has expired
		logger.Infof("CRL bundle retrieved from file cache with key %q has expired at %s", url, nextUpdate)
		return nil, corecrl.ErrCacheMiss
	}

	return &bundle, nil
}

// Set stores the CRL bundle in c with url as key.
func (c *FileCache) Set(ctx context.Context, url string, bundle *corecrl.Bundle) error {
	// sanity check
	if bundle == nil {
		return errors.New("failed to store crl bundle in file cache: bundle cannot be nil")
	}
	if bundle.BaseCRL == nil {
		return errors.New("failed to store crl bundle in file cache: bundle BaseCRL cannot be nil")
	}

	// actual content to be saved in the cache
	//
	// TODO: add DeltaCRL once notation-core-go supports it. Issue: https://github.com/notaryproject/notation-core-go/issues/228
	content := fileCacheContent{
		RawBaseCRL: bundle.BaseCRL.Raw,
	}

	// save content to tmp file
	tmpFile, err := os.CreateTemp("", tmpFileName)
	if err != nil {
		return fmt.Errorf("failed to store crl bundle in file cache: failed to create temp file: %w", err)
	}
	err = json.NewEncoder(tmpFile).Encode(content)
	if err != nil {
		return fmt.Errorf("failed to store crl bundle in file cache: failed to encode content: %w", err)
	}

	// rename is atomic on UNIX-like platforms
	err = os.Rename(tmpFile.Name(), filepath.Join(c.root, c.fileName(url)))
	if err != nil {
		return fmt.Errorf("failed to store crl bundle in file cache: %w", err)
	}
	return nil
}

// fileName returns the filename of the content stored in c
func (c *FileCache) fileName(url string) string {
	hash := sha256.Sum256([]byte(url))
	return hex.EncodeToString(hash[:])
}
