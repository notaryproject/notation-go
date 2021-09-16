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
	SignedAttributes   []Attribute `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttributes []Attribute `asn1:"optional,tag:1"`
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
