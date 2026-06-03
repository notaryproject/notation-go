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

package signer

import (
	"reflect"
	"sort"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// baseDescriptor returns a descriptor that mirrors the subject a notation
// client hands to a plugin for signing. Tests mutate copies of it to model a
// plugin that tampers with the payload during the generate-envelope flow.
func baseDescriptor() ocispec.Descriptor {
	return ocispec.Descriptor{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Digest:    digest.FromString("hello world"),
		Size:      11,
		Annotations: map[string]string{
			"identity": "test.registry.io/test:example",
		},
	}
}

func TestIsPayloadDescriptorValid(t *testing.T) {
	original := baseDescriptor()

	mismatchedDigest := baseDescriptor()
	mismatchedDigest.Digest = digest.FromString("tampered")

	mismatchedSize := baseDescriptor()
	mismatchedSize.Size = 22

	mismatchedMediaType := baseDescriptor()
	mismatchedMediaType.MediaType = "application/vnd.oci.image.index.v1+json"

	// A plugin is allowed to append annotations but not replace existing ones.
	overriddenAnnotation := baseDescriptor()
	overriddenAnnotation.Annotations = map[string]string{
		"identity": "attacker.registry.io/evil:latest",
	}

	addedAnnotation := baseDescriptor()
	addedAnnotation.Annotations = map[string]string{
		"identity": "test.registry.io/test:example",
		"foo":      "bar",
	}

	tests := map[string]struct {
		newDesc ocispec.Descriptor
		want    bool
	}{
		"matching descriptor is valid": {
			newDesc: baseDescriptor(),
			want:    true,
		},
		"appended annotation is valid": {
			newDesc: addedAnnotation,
			want:    true,
		},
		"mismatched digest is rejected": {
			newDesc: mismatchedDigest,
			want:    false,
		},
		"mismatched size is rejected": {
			newDesc: mismatchedSize,
			want:    false,
		},
		"mismatched mediaType is rejected": {
			newDesc: mismatchedMediaType,
			want:    false,
		},
		"overridden annotation is rejected": {
			newDesc: overriddenAnnotation,
			want:    false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := isPayloadDescriptorValid(original, tc.newDesc); got != tc.want {
				t.Fatalf("isPayloadDescriptorValid() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAreUnknownAttributesAdded(t *testing.T) {
	tests := map[string]struct {
		content string
		want    []string
	}{
		"all known attributes are accepted": {
			content: `{"targetArtifact":{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:abc","size":11,"urls":["https://example.com"],"annotations":{"identity":"test.registry.io/test:example"},"data":"aGk=","platform":{"architecture":"amd64","os":"linux"},"artifactType":"application/example"}}`,
			want:    []string{},
		},
		"unknown attribute inside descriptor is reported": {
			content: `{"targetArtifact":{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:abc","size":11,"injected":"value"}}`,
			want:    []string{"injected"},
		},
		"reserved-style attribute inside descriptor is reported": {
			content: `{"targetArtifact":{"digest":"sha256:abc","size":11,"$schema":"evil"}}`,
			want:    []string{"$schema"},
		},
		"unknown attribute at payload top level is reported": {
			content: `{"targetArtifact":{"digest":"sha256:abc","size":11},"extra":"value"}`,
			want:    []string{"extra"},
		},
		"unknown attributes at both levels are reported": {
			content: `{"targetArtifact":{"digest":"sha256:abc","size":11,"injected":"value"},"extra":"value"}`,
			want:    []string{"extra", "injected"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := areUnknownAttributesAdded([]byte(tc.content))
			sort.Strings(got)
			want := append([]string{}, tc.want...)
			sort.Strings(want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("areUnknownAttributesAdded() = %+q, want %+q", got, want)
			}
		})
	}
}
