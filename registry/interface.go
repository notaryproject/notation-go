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

// Package registry provides access to signatures in a registry
package registry

import (
	"context"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Repository provides registry functionalities for storage and retrieval
// of signature.
type Repository interface {
	// Resolve resolves a reference(tag or digest) to a manifest descriptor
	Resolve(ctx context.Context, reference string) (ocispec.Descriptor, error)

	// ListSignatures returns signature manifests filtered by fn given the
	// target artifact's manifest descriptor
	ListSignatures(ctx context.Context, desc ocispec.Descriptor, fn func(signatureManifests []ocispec.Descriptor) error) error

	// FetchSignatureBlob returns signature envelope blob and descriptor for
	// given signature manifest descriptor
	FetchSignatureBlob(ctx context.Context, desc ocispec.Descriptor) ([]byte, ocispec.Descriptor, error)

	// PushSignature creates and uploads an signature manifest along with its
	// linked signature envelope blob.
	PushSignature(ctx context.Context, mediaType string, blob []byte, subject ocispec.Descriptor, annotations map[string]string) (blobDesc, manifestDesc ocispec.Descriptor, err error)
}
