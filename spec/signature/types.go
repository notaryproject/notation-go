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

// KeyType defines a key type and size.
type KeyType string

// One of following supported specs
// https://github.com/notaryproject/notaryproject/blob/main/signature-specification.md#algorithm-selection
const (
	RSA_2048 KeyType = "RSA_2048"
	RSA_3072 KeyType = "RSA_3072"
	RSA_4096 KeyType = "RSA_4096"
	EC_256   KeyType = "EC_256"
	EC_384   KeyType = "EC_384"
	EC_512   KeyType = "EC_512"
)

// Hash returns the Hash associated k.
func (k KeyType) SignatureAlgorithm() SignatureAlgorithm {
	switch k {
	case RSA_2048:
		return RSASSA_PSS_SHA_256
	case RSA_3072:
		return RSASSA_PSS_SHA_384
	case RSA_4096:
		return RSASSA_PSS_SHA_512
	case EC_256:
		return ECDSA_SHA_256
	case EC_384:
		return ECDSA_SHA_384
	case EC_512:
		return ECDSA_SHA_512
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

// SignatureAlgorithm defines the supported signature algorithms.
type SignatureAlgorithm string

const (
	RSASSA_PSS_SHA_256 SignatureAlgorithm = "RSASSA_PSS_SHA_256"
	RSASSA_PSS_SHA_384 SignatureAlgorithm = "RSASSA_PSS_SHA_384"
	RSASSA_PSS_SHA_512 SignatureAlgorithm = "RSASSA_PSS_SHA_512"
	ECDSA_SHA_256      SignatureAlgorithm = "ECDSA_SHA_256"
	ECDSA_SHA_384      SignatureAlgorithm = "ECDSA_SHA_384"
	ECDSA_SHA_512      SignatureAlgorithm = "ECDSA_SHA_512"
)

// Hash returns the Hash associated s.
func (s SignatureAlgorithm) Hash() Hash {
	switch s {
	case RSASSA_PSS_SHA_256, ECDSA_SHA_256:
		return SHA256
	case RSASSA_PSS_SHA_384, ECDSA_SHA_384:
		return SHA384
	case RSASSA_PSS_SHA_512, ECDSA_SHA_512:
		return SHA512
	}
	return ""
}
