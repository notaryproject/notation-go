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

package file

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCopyToDir(t *testing.T) {
	t.Run("copy file", func(t *testing.T) {
		tempDir := t.TempDir()
		data := []byte("data")
		filename := filepath.Join(tempDir, "a", "file.txt")
		if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
			t.Fatal(err)
		}
		if err := WriteFile(filename, data); err != nil {
			t.Fatal(err)
		}

		destDir := filepath.Join(tempDir, "b")
		if err := CopyToDir(filename, destDir); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("source directory permission error", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("skipping test on Windows")
		}

		tempDir := t.TempDir()
		destDir := t.TempDir()
		data := []byte("data")
		filename := filepath.Join(tempDir, "a", "file.txt")
		if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
			t.Fatal(err)
		}
		if err := WriteFile(filename, data); err != nil {
			t.Fatal(err)
		}

		if err := os.Chmod(tempDir, 0000); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(tempDir, 0700)

		if err := CopyToDir(filename, destDir); err == nil {
			t.Fatal("should have error")
		}
	})

	t.Run("not a regular file", func(t *testing.T) {
		tempDir := t.TempDir()
		destDir := t.TempDir()
		if err := CopyToDir(tempDir, destDir); err == nil {
			t.Fatal("should have error")
		}
	})

	t.Run("source file permission error", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("skipping test on Windows")
		}

		tempDir := t.TempDir()
		destDir := t.TempDir()
		data := []byte("data")
		// prepare file
		filename := filepath.Join(tempDir, "a", "file.txt")
		if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
			t.Fatal(err)
		}
		if err := WriteFile(filename, data); err != nil {
			t.Fatal(err)
		}
		// forbid reading
		if err := os.Chmod(filename, 0000); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(filename, 0600)
		if err := CopyToDir(filename, destDir); err == nil {
			t.Fatal("should have error")
		}
	})

	t.Run("dest directory permission error", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("skipping test on Windows")
		}

		tempDir := t.TempDir()
		destTempDir := t.TempDir()
		data := []byte("data")
		// prepare file
		filename := filepath.Join(tempDir, "a", "file.txt")
		if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
			t.Fatal(err)
		}
		if err := WriteFile(filename, data); err != nil {
			t.Fatal(err)
		}
		// forbid dest directory operation
		if err := os.Chmod(destTempDir, 0000); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(destTempDir, 0700)
		if err := CopyToDir(filename, filepath.Join(destTempDir, "a")); err == nil {
			t.Fatal("should have error")
		}
	})

	t.Run("dest directory permission error 2", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("skipping test on Windows")
		}

		tempDir := t.TempDir()
		destTempDir := t.TempDir()
		data := []byte("data")
		// prepare file
		filename := filepath.Join(tempDir, "a", "file.txt")
		if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
			t.Fatal(err)
		}
		if err := WriteFile(filename, data); err != nil {
			t.Fatal(err)
		}
		// forbid writing to destTempDir
		if err := os.Chmod(destTempDir, 0000); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(destTempDir, 0700)
		if err := CopyToDir(filename, destTempDir); err == nil {
			t.Fatal("should have error")
		}
	})

	t.Run("copy file and check content", func(t *testing.T) {
		tempDir := t.TempDir()
		data := []byte("data")
		filename := filepath.Join(tempDir, "a", "file.txt")
		if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
			t.Fatal(err)
		}
		if err := WriteFile(filename, data); err != nil {
			t.Fatal(err)
		}

		destDir := filepath.Join(tempDir, "b")
		if err := CopyToDir(filename, destDir); err != nil {
			t.Fatal(err)
		}
		validFileContent(t, filepath.Join(destDir, "file.txt"), data)
	})
}

func TestFileNameWithoutExtension(t *testing.T) {
	input := "testfile.tar.gz"
	expectedOutput := "testfile.tar"
	actualOutput := TrimFileExtension(input)
	if actualOutput != expectedOutput {
		t.Errorf("expected '%s', but got '%s'", expectedOutput, actualOutput)
	}
}

func TestWriteFile(t *testing.T) {
	tempDir := t.TempDir()
	content := []byte("test WriteFile")

	t.Run("permission denied", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("skipping test on Windows")
		}
		err := os.Chmod(tempDir, 0)
		if err != nil {
			t.Fatal(err)
		}
		err = WriteFile(filepath.Join(tempDir, "testFile"), content)
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("expected permission denied error, but got %s", err)
		}
		err = os.Chmod(tempDir, 0700)
		if err != nil {
			t.Fatal(err)
		}
	})
}

func validFileContent(t *testing.T, filename string, content []byte) {
	b, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, b) {
		t.Fatal("file content is not correct")
	}
}
