package timestamp

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/notaryproject/notation-go-lib/internal/crypto/cms"
	"github.com/notaryproject/notation-go-lib/internal/crypto/hashutil"
	"github.com/notaryproject/notation-go-lib/internal/crypto/oid"
	asn1util "github.com/notaryproject/notation-go-lib/internal/encoding/asn1"
)

// SignedToken is a parsed timestamp token with signatures.
type SignedToken cms.ParsedSignedData

// ParseSignedToken parses ASN.1 BER-encoded structure to SignedToken
// without verification.
// Callers should invoke Verify to verify the content before comsumption.
func ParseSignedToken(data []byte) (*SignedToken, error) {
	data, err := asn1util.ConvertToDER(data)
	if err != nil {
		return nil, err
	}
	signed, err := cms.ParseSignedData(data)
	if err != nil {
		return nil, err
	}
	if !oid.TSTInfo.Equal(signed.ContentType) {
		return nil, fmt.Errorf("unexpected content type: %v", signed.ContentType)
	}
	return (*SignedToken)(signed), nil
}

// Info returns the timestamping information.
func (t *SignedToken) Info() (*TSTInfo, error) {
	var info TSTInfo
	if _, err := asn1.Unmarshal(t.Content, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// Accuracy ::= SEQUENCE {
//  seconds     INTEGER             OPTIONAL,
//  millis  [0] INTEGER (1..999)    OPTIONAL,
//  micros  [1] INTEGER (1..999)    OPTIONAL }
type Accuracy struct {
	Seconds      int `asn1:"optional"`
	Milliseconds int `asn1:"optional,tag:0"`
	Microseconds int `asn1:"optional,tag:1"`
}

// TSTInfo ::= SEQUENCE {
//  version         INTEGER                 { v1(1) },
//  policy          TSAPolicyId,
//  messageImprint  MessageImprint,
//  serialNumber    INTEGER,
//  genTime         GeneralizedTime,
//  accuracy        Accuracy                OPTIONAL,
//  ordering        BOOLEAN                 DEFAULT FALSE,
//  nonce           INTEGER                 OPTIONAL,
//  tsa             [0] GeneralName         OPTIONAL,
//  extensions      [1] IMPLICIT Extensions OPTIONAL }
type TSTInfo struct {
	Version        int // fixed to 1 as defined in RFC 3161 2.4.2 Response Format
	Policy         asn1.ObjectIdentifier
	MessageImprint MessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time        `asn1:"generalized"`
	Accuracy       Accuracy         `asn1:"optional"`
	Ordering       bool             `asn1:"optional,default:false"`
	Nonce          *big.Int         `asn1:"optional"`
	TSA            asn1.RawValue    `asn1:"optional,tag:0"`
	Extensions     []pkix.Extension `asn1:"optional,tag:1"`
}

// Verify verifies the message against the timestamp token information.
func (tst *TSTInfo) Verify(message []byte) error {
	hashAlg := tst.MessageImprint.HashAlgorithm.Algorithm
	hash, ok := oid.ConvertToHash(hashAlg)
	if !ok {
		return fmt.Errorf("unrecognized hash algorithm: %v", hashAlg)
	}
	messageDigest, err := hashutil.ComputeHash(hash, message)
	if err != nil {
		return err
	}
	if !bytes.Equal(tst.MessageImprint.HashedMessage, messageDigest) {
		return errors.New("mismatch message digest")
	}
	return nil
}

// Timestamp returns the timestamp by TSA and its accuracy.
func (tst *TSTInfo) Timestamp() (time.Time, time.Duration) {
	accuracy := time.Duration(tst.Accuracy.Seconds)*time.Second +
		time.Duration(tst.Accuracy.Milliseconds)*time.Millisecond +
		time.Duration(tst.Accuracy.Microseconds)*time.Microsecond
	return tst.GenTime, accuracy
}
