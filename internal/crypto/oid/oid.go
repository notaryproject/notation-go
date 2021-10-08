// Package oid collects object identifiers for crypto algorithms.
package oid

import "encoding/asn1"

// OIDs for hash algorithms
var (
	// SHA1 (id-sha1) is defined in RFC 8017 B.1 Hash Functions
	SHA1 = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}

	// SHA256 (id-sha256) is defined in RFC 8017 B.1 Hash Functions
	SHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

	// SHA384 (id-sha384) is defined in RFC 8017 B.1 Hash Functions
	SHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}

	// SHA512 (id-sha512) is defined in RFC 8017 B.1 Hash Functions
	SHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// OIDs for signature algorithms
var (
	// RSA is defined in RFC 8017 C ASN.1 Module
	RSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}

	// SHA1WithRSA is defined in RFC 8017 C ASN.1 Module
	SHA1WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}

	// SHA256WithRSA is defined in RFC 8017 C ASN.1 Module
	SHA256WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}

	// SHA384WithRSA is defined in RFC 8017 C ASN.1 Module
	SHA384WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}

	// SHA512WithRSA is defined in RFC 8017 C ASN.1 Module
	SHA512WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}

	// ECDSAWithSHA1 is defined in ANSI X9.62
	ECDSAWithSHA1 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}

	// ECDSAWithSHA256 is defined in RFC 5758 3.2 ECDSA Signature Algorithm
	ECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}

	// ECDSAWithSHA384 is defined in RFC 5758 3.2 ECDSA Signature Algorithm
	ECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}

	// ECDSAWithSHA512 is defined in RFC 5758 3.2 ECDSA Signature Algorithm
	ECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

// OIDs defined in RFC 5652 Cryptographic Message Syntax (CMS)
var (
	// SignedData (id-signedData) is defined in RFC 5652 5.1 SignedData Type
	SignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

	// ContentType (id-ct-contentType) is defined in RFC 5652 3 General Syntax
	ContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}

	// MessageDigest (id-messageDigest) is defined in RFC 5652 11.2 Message Digest
	MessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

	// SigningTime (id-signingTime) is defined in RFC 5652 11.3 Signing Time
	SigningTime = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
)

// TSTInfo (id-ct-TSTInfo) is defined in RFC 3161 2.4.2 Response Format
var TSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
