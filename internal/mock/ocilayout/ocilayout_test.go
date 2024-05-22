package ocilayout

import (
	"os"
	"testing"
)

func TestCopy(t *testing.T) {
	t.Run("empty oci layout", func(t *testing.T) {
		_, err := Copy("", "", "v2")
		if err == nil {
			t.Errorf("expected error, got nil")
		}
	})

	t.Run("invalid target path", func(t *testing.T) {
		tempDir := t.TempDir()
		// change the permission of the tempDir to make it invalid
		if err := os.Chmod(tempDir, 0); err != nil {
			t.Fatalf("failed to change the permission of the tempDir: %v", err)
		}
		_, err := Copy("../../testdata/oci-layout", tempDir, "v2")
		if err == nil {
			t.Errorf("expected error, got nil")
		}
		// clean tempDir
		if err := os.Chmod(tempDir, 0755); err != nil {
			t.Fatalf("failed to change the permission of the tempDir: %v", err)
		}
	})

	t.Run("copy failed", func(t *testing.T) {
		tempDir := t.TempDir()
		_, err := Copy("../../testdata/oci-layout", tempDir, "v3")
		if err == nil {
			t.Errorf("expected error, got nil")
		}
	})

	t.Run("copy success", func(t *testing.T) {
		tempDir := t.TempDir()
		_, err := Copy("../../testdata/oci-layout", tempDir, "v2")
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})
}
