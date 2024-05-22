package ocilayout

import (
	"context"
	"os"
	"path/filepath"

	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/oci"
)

// Copy creates a temporary OCI layout for testing
// and returns the path to the layout.
func Copy(sourcePath string, destinationPath string) (string, error) {
	ctx := context.Background()
	destPath := filepath.Join(destinationPath, "notation", "oci-layout")

	srcStore, err := oci.NewFromFS(ctx, os.DirFS(sourcePath))
	if err != nil {
		return "", err
	}

	// create a dest store for store the generated oci layout.
	destStore, err := oci.New(destPath)
	if err != nil {
		return "", err
	}

	// copy data
	_, err = oras.ExtendedCopy(ctx, srcStore, "v2", destStore, "", oras.DefaultExtendedCopyOptions)
	if err != nil {
		return "", err
	}

	return destPath, nil
}
