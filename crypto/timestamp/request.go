package timestamp

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/notaryproject/notation-go/internal/crypto/oid"
	digest "github.com/opencontainers/go-digest"
)

// MessageImprint contains the hash of the datum to be time-stamped.
// MessageImprint ::= SEQUENCE {
//  hashAlgorithm   AlgorithmIdentifier,
//  hashedMessage   OCTET STRING }
type MessageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// Request is a time-stamping request.
// TimeStampReq ::= SEQUENCE {
//  version         INTEGER                 { v1(1) },
//  messageImprint  MessageImprint,
//  reqPolicy       TSAPolicyID              OPTIONAL,
//  nonce           INTEGER                  OPTIONAL,
//  certReq         BOOLEAN                  DEFAULT FALSE,
//  extensions      [0] IMPLICIT Extensions  OPTIONAL }
type Request struct {
	Version        int // fixed to 1 as defined in RFC 3161 2.4.1 Request Format
	MessageImprint MessageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     []pkix.Extension      `asn1:"optional,tag:0"`
}

// NewRequest creates a request based on the given digest.
func NewRequest(contentDigest digest.Digest) (*Request, error) {
	hashAlgorithm, err := getOIDFromDigestAlgorithm(contentDigest.Algorithm())
	if err != nil {
		return nil, err
	}
	hashedMessage, err := hex.DecodeString(contentDigest.Encoded())
	if err != nil {
		return nil, err
	}
	return &Request{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: hashAlgorithm,
			},
			HashedMessage: hashedMessage,
		},
		CertReq: true,
	}, nil
}

// NewRequestFromBytes creates a request based on the given byte slice.
func NewRequestFromBytes(content []byte) (*Request, error) {
	return NewRequest(digest.FromBytes(content))
}

// NewRequestFromString creates a request based on the given string.
func NewRequestFromString(content string) (*Request, error) {
	return NewRequest(digest.FromString(content))
}

// MarshalBinary encodes the request to binary form.
// This method implements encoding.BinaryMarshaler
func (r *Request) MarshalBinary() ([]byte, error) {
	if r == nil {
		return nil, errors.New("nil request")
	}
	return asn1.Marshal(*r)
}

// UnmarshalBinary decodes the request from binary form.
// This method implements encoding.BinaryUnmarshaler
func (r *Request) UnmarshalBinary(data []byte) error {
	_, err := asn1.Unmarshal(data, r)
	return err
}

// getOIDFromDigestAlgorithm returns corresponding ASN.1 OID for the given digest algorithm.
func getOIDFromDigestAlgorithm(alg digest.Algorithm) (asn1.ObjectIdentifier, error) {
	switch alg {
	case digest.SHA256:
		return oid.SHA256, nil
	case digest.SHA384:
		return oid.SHA384, nil
	case digest.SHA512:
		return oid.SHA512, nil
	}
	return nil, digest.ErrDigestUnsupported
}
