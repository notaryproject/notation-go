package asn1

import (
	"bytes"
	"testing"
)

func Test_encodeLength(t *testing.T) {
	tests := []struct {
		name    string
		length  int
		want    []byte
		wantErr bool
	}{
		{
			name:   "zero length",
			length: 0,
			want:   []byte{0x00},
		},
		{
			name:   "short form",
			length: 42,
			want:   []byte{0x2a},
		},
		{
			name:   "short form in max",
			length: 127,
			want:   []byte{0x7f},
		},
		{
			name:   "long form in min",
			length: 128,
			want:   []byte{0x81, 0x80},
		},
		{
			name:   "long form",
			length: 1234567890,
			want:   []byte{0x84, 0x49, 0x96, 0x02, 0xd2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := bytes.NewBuffer(nil)
			if err := encodeLength(buf, tt.length); (err != nil) != tt.wantErr {
				t.Errorf("encodeLength() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got := buf.Bytes(); !bytes.Equal(got, tt.want) {
				t.Errorf("encoded length = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_decodeIdentifier(t *testing.T) {
	tests := []struct {
		name    string
		encoded []byte
		want    []byte
		wantErr bool
	}{
		{
			name:    "empty identifier",
			wantErr: true,
		},
		{
			name:    "low-tag-number form",
			encoded: []byte{0x0b},
			want:    []byte{0x0b},
		},
		{
			name:    "no extra read in low-tag-number form",
			encoded: []byte{0x0b, 0x42},
			want:    []byte{0x0b},
		},
		{
			name:    "high-tag-number form",
			encoded: []byte{0x1f, 0x17, 0xdf},
			want:    []byte{0x1f, 0x17, 0xdf}, // tag: 0x012345
		},
		{
			name:    "no extra read in high-tag-number form",
			encoded: []byte{0x1f, 0x17, 0xdf, 0x42},
			want:    []byte{0x1f, 0x17, 0xdf}, // tag: 0x012345
		},
		{
			name:    "high-tag-number form (no termination)",
			encoded: []byte{0x1f, 0x17, 0x5f},
			wantErr: true,
		},
		{
			name:    "high-tag-number form (EOF)",
			encoded: []byte{0x1f, 0x17},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.encoded)
			got, err := decodeIdentifier(r)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeIdentifier() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("decodeIdentifier() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_decodeLength(t *testing.T) {
	tests := []struct {
		name    string
		encoded []byte
		want    int
		wantErr bool
	}{
		{
			name:    "empty length",
			wantErr: true,
		},
		{
			name:    "short form",
			encoded: []byte{0x2a},
			want:    42,
		},
		{
			name:    "no extra read in short form",
			encoded: []byte{0x2a, 0x42},
			want:    42,
		},
		{
			name:    "long form",
			encoded: []byte{0x84, 0x49, 0x96, 0x02, 0xd2},
			want:    1234567890,
		},
		{
			name:    "long form in BER",
			encoded: []byte{0x81, 0x2a},
			want:    42,
		},
		{
			name:    "no extra read in long form",
			encoded: []byte{0x84, 0x49, 0x96, 0x02, 0xd2, 0x42},
			want:    1234567890,
		},
		{
			name:    "long form (indefinite)",
			encoded: []byte{0x80, 0x42, 0x00, 0x00},
			wantErr: true,
		},
		{
			name:    "long form (EOF)",
			encoded: []byte{0x84, 0x49, 0x96, 0x02},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.encoded)
			got, err := decodeLength(r)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeLength() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("decodeLength() = %v, want %v", got, tt.want)
			}
		})
	}
}
