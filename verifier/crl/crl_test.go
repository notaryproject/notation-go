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

package crl

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	corecrl "github.com/notaryproject/notation-core-go/revocation/crl"
	"github.com/notaryproject/notation-core-go/testhelper"
)

func TestFileCache(t *testing.T) {
	now := time.Now()
	certChain := testhelper.GetRevokableRSAChainWithRevocations(2, false, true)
	crlBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		NextUpdate: now.Add(time.Hour),
	}, certChain[1].Cert, certChain[1].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	baseCRL, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	root := t.TempDir()
	cache, err := NewFileCache(root)
	t.Run("NewFileCache", func(t *testing.T) {
		if err != nil {
			t.Fatalf("expected no error, but got %v", err)
		}
		if cache.root != root {
			t.Fatalf("expected root %v, but got %v", root, cache.root)
		}
	})

	key := "testKey"
	bundle := &corecrl.Bundle{BaseCRL: baseCRL}
	t.Run("comformance", func(t *testing.T) {
		if err := cache.Set(ctx, key, bundle); err != nil {
			t.Fatal(err)
		}
		retrievedBundle, err := cache.Get(ctx, key)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(retrievedBundle.BaseCRL.Raw, bundle.BaseCRL.Raw) {
			t.Fatalf("expected bundle %+v, but got %+v", bundle.BaseCRL, retrievedBundle.BaseCRL)
		}
	})
}

func TestNewFileCacheFailed(t *testing.T) {
	tempDir := t.TempDir()
	t.Run("without permission to create cache directory", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("skipping test on Windows")
		}

		if err := os.Chmod(tempDir, 0); err != nil {
			t.Fatal(err)
		}
		root := filepath.Join(tempDir, "test")
		_, err := NewFileCache(root)
		if !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("expected permission denied error, but got %v", err)
		}
		// restore permission
		if err := os.Chmod(tempDir, 0755); err != nil {
			t.Fatalf("failed to change permission: %v", err)
		}
	})
}

func TestGetFailed(t *testing.T) {
	tempDir := t.TempDir()
	cache, err := NewFileCache(tempDir)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("key does not exist", func(t *testing.T) {
		_, err := cache.Get(context.Background(), "nonExistKey")
		if !errors.Is(err, corecrl.ErrCacheMiss) {
			t.Fatalf("expected ErrCacheMiss, but got %v", err)
		}
	})

	invalidFile := filepath.Join(tempDir, cache.fileName("invalid"))
	if err := os.WriteFile(invalidFile, []byte("invalid"), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	t.Run("no permission to read file", func(t *testing.T) {
		if err := os.Chmod(invalidFile, 0); err != nil {
			t.Fatal(err)
		}
		_, err := cache.Get(context.Background(), "invalid")
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("expected permission denied error, but got %v", err)
		}
		// restore permission
		if err := os.Chmod(invalidFile, 0755); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("invalid content", func(t *testing.T) {
		_, err := cache.Get(context.Background(), "invalid")
		expectedErrMsg := "failed to decode file retrieved from file cache: invalid character 'i' looking for beginning of value"
		if err == nil || err.Error() != expectedErrMsg {
			t.Fatalf("expected %s, but got %v", expectedErrMsg, err)
		}
	})

	now := time.Now()
	certChain := testhelper.GetRevokableRSAChainWithRevocations(2, false, true)
	crlBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1),
	}, certChain[1].Cert, certChain[1].PrivateKey)
	if err != nil {
		t.Fatalf("failed to create base CRL: %v", err)
	}
	baseCRL, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		t.Fatalf("failed to parse base CRL: %v", err)
	}

	t.Run("invalid RawBaseCRL of content", func(t *testing.T) {
		content := fileCacheContent{
			RawBaseCRL: []byte("invalid"),
		}
		b, err := json.Marshal(content)
		if err != nil {
			t.Fatal(err)
		}
		invalidBundleFile := filepath.Join(tempDir, cache.fileName("invalidBundle"))
		if err := os.WriteFile(invalidBundleFile, b, 0644); err != nil {
			t.Fatalf("failed to write file: %v", err)
		}
		_, err = cache.Get(context.Background(), "invalidBundle")
		expectedErrMsg := "failed to parse base CRL of file retrieved from file cache: x509: malformed crl"
		if err == nil || err.Error() != expectedErrMsg {
			t.Fatalf("expected %s, but got %v", expectedErrMsg, err)
		}
	})

	t.Run("bundle with invalid NextUpdate", func(t *testing.T) {
		ctx := context.Background()
		expiredBundle := &corecrl.Bundle{BaseCRL: baseCRL}
		if err := cache.Set(ctx, "expiredKey", expiredBundle); err != nil {
			t.Fatal(err)
		}
		_, err = cache.Get(ctx, "expiredKey")
		expectedErrMsg := "crl bundle retrieved from file cache does not contain BaseCRL NextUpdate"
		if err == nil || err.Error() != expectedErrMsg {
			t.Fatalf("expected %s, but got %v", expectedErrMsg, err)
		}
	})

	crlBytes, err = x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		NextUpdate: now.Add(-time.Hour),
	}, certChain[1].Cert, certChain[1].PrivateKey)
	if err != nil {
		t.Fatalf("failed to create base CRL: %v", err)
	}
	baseCRL, err = x509.ParseRevocationList(crlBytes)
	if err != nil {
		t.Fatalf("failed to parse base CRL: %v", err)
	}
	t.Run("bundle in cache has expired", func(t *testing.T) {
		ctx := context.Background()
		expiredBundle := &corecrl.Bundle{BaseCRL: baseCRL}
		if err := cache.Set(ctx, "expiredKey", expiredBundle); err != nil {
			t.Fatal(err)
		}
		_, err = cache.Get(ctx, "expiredKey")
		if !errors.Is(err, corecrl.ErrCacheMiss) {
			t.Fatalf("expected ErrCacheMiss, but got %v", err)
		}
	})
}

func TestSetFailed(t *testing.T) {
	tempDir := t.TempDir()
	cache, err := NewFileCache(tempDir)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	certChain := testhelper.GetRevokableRSAChainWithRevocations(2, false, true)
	crlBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		NextUpdate: now.Add(time.Hour),
	}, certChain[1].Cert, certChain[1].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	baseCRL, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	key := "testKey"

	t.Run("nil bundle", func(t *testing.T) {
		err := cache.Set(ctx, key, nil)
		expectedErrMsg := "failed to store crl bundle in file cache: bundle cannot be nil"
		if err == nil || err.Error() != expectedErrMsg {
			t.Fatalf("expected %s, but got %v", expectedErrMsg, err)
		}
	})

	t.Run("nil bundle BaseCRL", func(t *testing.T) {
		bundle := &corecrl.Bundle{}
		err := cache.Set(ctx, key, bundle)
		expectedErrMsg := "failed to store crl bundle in file cache: bundle BaseCRL cannot be nil"
		if err == nil || err.Error() != expectedErrMsg {
			t.Fatalf("expected %s, but got %v", expectedErrMsg, err)
		}
	})

	t.Run("failed to write into cache due to permission denied", func(t *testing.T) {
		if err := os.Chmod(tempDir, 0); err != nil {
			t.Fatal(err)
		}
		bundle := &corecrl.Bundle{BaseCRL: baseCRL}
		err := cache.Set(ctx, key, bundle)
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("expected permission denied error, but got %v", err)
		}
		// restore permission
		if err := os.Chmod(tempDir, 0755); err != nil {
			t.Fatalf("failed to change permission: %v", err)
		}
	})
}
