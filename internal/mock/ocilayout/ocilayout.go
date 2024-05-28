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

package ocilayout

import (
	"context"
	"os"

	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/oci"
)

// Copy creates a temporary OCI layout for testing
// and returns the path to the layout.
func Copy(sourcePath, destPath, tag string) error {
	ctx := context.Background()

	srcStore, err := oci.NewFromFS(ctx, os.DirFS(sourcePath))
	if err != nil {
		return err
	}

	// create a dest store for store the generated oci layout.
	destStore, err := oci.New(destPath)
	if err != nil {
		return err
	}

	// copy data
	_, err = oras.ExtendedCopy(ctx, srcStore, tag, destStore, "", oras.DefaultExtendedCopyOptions)
	if err != nil {
		return err
	}

	return nil
}
