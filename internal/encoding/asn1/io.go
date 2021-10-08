package asn1

import "io"

// ValueReader is the interface for reading a value.
type ValueReader interface {
	io.Reader
	io.ByteScanner
}

// ValueWriter is the interface for writing a value.
type ValueWriter interface {
	io.Writer
	io.ByteWriter
}

// limitedValueReader limits the amount of data returned.
type limitedValueReader struct {
	io.LimitedReader
	S io.ByteScanner
}

// LimitValueReader returns a ValueReader, which limits the amount of data returned.
func LimitValueReader(r ValueReader, n int64) ValueReader {
	return &limitedValueReader{
		LimitedReader: io.LimitedReader{
			R: r,
			N: n,
		},
		S: r,
	}
}

func (l *limitedValueReader) ReadByte() (c byte, err error) {
	if l.N <= 0 {
		return 0, io.EOF
	}
	c, err = l.S.ReadByte()
	if err == nil {
		l.N--
	}
	return
}

func (l *limitedValueReader) UnreadByte() (err error) {
	err = l.S.UnreadByte()
	if err == nil {
		l.N++
	}
	return
}
