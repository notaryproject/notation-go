package asn1

import "io"

// isPrimitive checks the primitive flag in the identifier.
// Returns true if the value is primitive.
func isPrimitive(identifier byte) bool {
	return identifier&0x20 == 0
}

// encodedLengthSize gives the number of octets used for encoding the length.
func encodedLengthSize(length int) int {
	if length < 0x80 {
		return 1
	}

	lengthSize := 1
	for ; length > 0; lengthSize++ {
		length >>= 8
	}
	return lengthSize
}

// encodeLength encodes length octets in DER.
func encodeLength(w io.ByteWriter, length int) error {
	// DER restriction: short form must be used for length less than 128
	if length < 0x80 {
		return w.WriteByte(byte(length))
	}

	// DER restriction: long form must be encoded in the minimum number of octets
	lengthSize := encodedLengthSize(length)
	err := w.WriteByte(0x80 | byte(lengthSize-1))
	if err != nil {
		return err
	}
	for i := lengthSize - 1; i > 0; i-- {
		if err = w.WriteByte(byte(length >> (8 * (i - 1)))); err != nil {
			return err
		}
	}
	return nil
}

// decodeIdentifier decodes identifier octets.
func decodeIdentifier(r io.ByteReader) ([]byte, error) {
	b, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	// low-tag-number form
	identifier := []byte{b}

	// high-tag-number form
	if b&0x1f == 0x1f {
		for {
			b, err = r.ReadByte()
			if err != nil {
				if err == io.EOF {
					return nil, ErrEarlyEOF
				}
				return nil, err
			}
			identifier = append(identifier, b)
			if b&0x80 != 0 {
				break
			}
		}
	}

	return identifier, nil
}

// decodeLength decodes length octets.
// Indefinite length is not supported
func decodeLength(r io.ByteReader) (int, error) {
	b, err := r.ReadByte()
	if err != nil {
		if err == io.EOF {
			return 0, ErrEarlyEOF
		}
		return 0, err
	}
	switch {
	case b < 0x80:
		// short form
		return int(b), nil
	case b == 0x80:
		// Indefinite-length method is not supported.
		return 0, ErrUnsupportedLength
	}

	// long form
	n := int(b & 0x7f)
	if n > 4 {
		// length must fit the memory space of the int type.
		return 0, ErrUnsupportedLength
	}
	var length int
	for i := 0; i < n; i++ {
		b, err = r.ReadByte()
		if err != nil {
			if err == io.EOF {
				return 0, ErrEarlyEOF
			}
			return 0, err
		}
		length = (length << 8) | int(b)
	}
	if length < 0 {
		// double check in case that length is over 31 bits.
		return 0, ErrUnsupportedLength
	}
	return length, nil
}
