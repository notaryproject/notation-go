// Package cms verifies signatures in Cryptographic Message Syntax (CMS) / PKCS7
// defined in RFC 5652.
package cms

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
)

// ContentInfo ::= SEQUENCE {
//  contentType ContentType,
//  content     [0] EXPLICIT ANY DEFINED BY contentType }
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// SignedData ::= SEQUENCE {
//  version             CMSVersion,
//  digestAlgorithms    DigestAlgorithmIdentifiers,
//  encapContentInfo    EncapsulatedContentInfo,
//  certificates        [0] IMPLICIT CertificateSet             OPTIONAL,
//  crls                [1] IMPLICIT CertificateRevocationLists OPTIONAL,
//  signerInfos         SignerInfos }
type SignedData struct {
	Version                    int
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapsulatedContentInfo    EncapsulatedContentInfo
	Certificates               asn1.RawValue          `asn1:"optional,tag:0"`
	CRLs                       []pkix.CertificateList `asn1:"optional,tag:1"`
	SignerInfos                []SignerInfo           `asn1:"set"`
}

// EncapsulatedContentInfo ::= SEQUENCE {
//  eContentType    ContentType,
//  eContent        [0] EXPLICIT OCTET STRING   OPTIONAL }
type EncapsulatedContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     []byte `asn1:"explicit,optional,tag:0"`
}

// SignerInfo ::= SEQUENCE {
//  version             CMSVersion,
//  sid                 SignerIdentifier,
//  digestAlgorithm     DigestAlgorithmIdentifier,
//  signedAttrs         [0] IMPLICIT SignedAttributes   OPTIONAL,
//  signatureAlgorithm  SignatureAlgorithmIdentifier,
//  signature           SignatureValue,
//  unsignedAttrs       [1] IMPLICIT UnsignedAttributes OPTIONAL }
// Only version 1 is supported. As defined in RFC 5652 5.3, SignerIdentifier
// is IssuerAndSerialNumber when version is 1.
type SignerInfo struct {
	Version            int
	SignerIdentifier   IssuerAndSerialNumber
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttributes   Attributes `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttributes Attributes `asn1:"optional,tag:1"`
}

// IssuerAndSerialNumber ::= SEQUENCE {
//  issuer          Name,
//  serialNumber    CertificateSerialNumber }
type IssuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// Attribute ::= SEQUENCE {
//  attrType    OBJECT IDENTIFIER,
//  attrValues  SET OF AttributeValue }
type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

// Attribute ::= SET SIZE (1..MAX) OF Attribute
type Attributes []Attribute

// TryGet tries to find the attribute by the given identifier, parse and store
// the result in the value pointed to by out.
func (a Attributes) TryGet(identifier asn1.ObjectIdentifier, out interface{}) error {
	for _, attribute := range a {
		if identifier.Equal(attribute.Type) {
			_, err := asn1.Unmarshal(attribute.Values.Bytes, out)
			return err
		}
	}
	return ErrAttributeNotFound
}
