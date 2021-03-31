package registry

import (
	"os"

	"github.com/opencontainers/go-digest"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
)

// DescriptorFromBytes computes the basic descriptor from the given bytes
func DescriptorFromBytes(data []byte) oci.Descriptor {
	return oci.Descriptor{
		Digest: digest.FromBytes(data),
		Size:   int64(len(data)),
	}
}

// DescriptorFromFile computes the basic descriptor from the file
func DescriptorFromFile(path string) (oci.Descriptor, error) {
	file, err := os.Open(path)
	if err != nil {
		return oci.Descriptor{}, err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return oci.Descriptor{}, err
	}

	digest, err := digest.FromReader(file)
	if err != nil {
		return oci.Descriptor{}, err
	}

	return oci.Descriptor{
		Digest: digest,
		Size:   stat.Size(),
	}, nil
}
