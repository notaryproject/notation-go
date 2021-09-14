// Package asn1 decodes BER-encoded ASN.1 data structures and encodes in DER.
// Note: DER is a subset of BER.
// Reference: http://luca.ntop.org/Teaching/Appunti/asn1.html
package asn1

import (
	"bytes"
	"encoding/asn1"
)

// Common errors
var (
	ErrEarlyEOF          = asn1.SyntaxError{Msg: "early EOF"}
	ErrExpectConstructed = asn1.SyntaxError{Msg: "constructed value expected"}
	ErrExpectPrimitive   = asn1.SyntaxError{Msg: "primitive value expected"}
	ErrUnsupportedLength = asn1.StructuralError{Msg: "length method not supported"}
)

// Value represents an ASN.1 value.
type Value interface {
	// Encode encodes the value to the value writer in DER.
	Encode(ValueWriter) error

	// EncodedLen returns the length in bytes of the encoded data.
	EncodedLen() int
}

// Decode decodes BER-encoded ASN.1 data structures.
func Decode(r ValueReader) (Value, error) {
	peekIdentifier, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if err = r.UnreadByte(); err != nil {
		return nil, err
	}
	if isPrimitive(peekIdentifier) {
		return DecodePrimitive(r)
	}
	return DecodeConstructed(r)
}

// ConvertToDER converts BER-encoded ASN.1 data structures to DER-encoded.
func ConvertToDER(ber []byte) ([]byte, error) {
	v, err := Decode(bytes.NewReader(ber))
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(make([]byte, 0, v.EncodedLen()))
	if err = v.Encode(buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
