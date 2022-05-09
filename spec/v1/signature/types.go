package signature

import "crypto"

const (
	// MediaTypeDescriptor describes the media type of the descriptor.
	MediaTypeDescriptor = "application/vnd.oci.descriptor.v1+json"
)

// Descriptor describes the content signed or to be signed.
type Descriptor struct {
	// The media type of the targeted content.
	MediaType string `json:"mediaType"`

	// The digest of the targeted content.
	Digest string `json:"digest"`

	// Specifies the size in bytes of the blob.
	Size int64 `json:"size"`

	// Contains optional user defined attributes.
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Equal reports whether d and t points to the same content.
func (d Descriptor) Equal(t Descriptor) bool {
	return d.MediaType == t.MediaType && d.Digest == t.Digest && d.Size == t.Size
}

// Key defines a key type and size.
type Key string

// One of following supported specs
// https://github.com/notaryproject/notaryproject/blob/main/signature-specification.md#algorithm-selection
const (
	RSA_2048 Key = "RSA_2048"
	RSA_3072 Key = "RSA_3072"
	RSA_4096 Key = "RSA_4096"
	EC_256   Key = "EC_256"
	EC_384   Key = "EC_384"
	EC_512   Key = "EC_512"
)

// Hash returns the Hash associated k.
func (k Key) Hash() Hash {
	switch k {
	case RSA_2048, EC_256:
		return SHA256
	case RSA_3072, EC_384:
		return SHA384
	case RSA_4096, EC_512:
		return SHA512
	}
	return ""
}

// Hash algorithm associated with the key spec.
type Hash string

const (
	SHA256 Hash = "SHA_256"
	SHA384 Hash = "SHA_384"
	SHA512 Hash = "SHA_512"
)

// HashFunc returns the Hash associated k.
func (h Hash) HashFunc() crypto.Hash {
	switch h {
	case SHA256:
		return crypto.SHA256
	case SHA384:
		return crypto.SHA384
	case SHA512:
		return crypto.SHA512
	}
	return 0
}
