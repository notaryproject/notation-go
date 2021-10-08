package asn1

import "io"

// ConstructedValue represents a value in constructed encoding.
type ConstructedValue struct {
	identifier []byte
	length     int
	members    []Value
}

// Encode encodes the constructed value to the value writer in DER.
func (v ConstructedValue) Encode(w ValueWriter) error {
	_, err := w.Write(v.identifier)
	if err != nil {
		return err
	}
	if err = encodeLength(w, v.length); err != nil {
		return err
	}
	for _, value := range v.members {
		if err = value.Encode(w); err != nil {
			return err
		}
	}
	return nil
}

// EncodedLen returns the length in bytes of the encoded data.
func (v ConstructedValue) EncodedLen() int {
	return len(v.identifier) + encodedLengthSize(v.length) + v.length
}

// DecodeConstructed decodes a constructed value in BER.
func DecodeConstructed(r ValueReader) (Value, error) {
	identifier, err := decodeIdentifier(r)
	if err != nil {
		return nil, err
	}
	if isPrimitive(identifier[0]) {
		return nil, ErrExpectConstructed
	}
	expectedLength, err := decodeLength(r)
	if err != nil {
		return nil, err
	}

	var members []Value
	encodedLength := 0
	r = LimitValueReader(r, int64(expectedLength))
	for {
		value, err := Decode(r)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		members = append(members, value)
		encodedLength += value.EncodedLen()
	}

	return ConstructedValue{
		identifier: identifier,
		length:     encodedLength,
		members:    members,
	}, nil
}
