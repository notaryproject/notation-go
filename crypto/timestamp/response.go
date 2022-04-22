package timestamp

import (
	"encoding/asn1"
	"errors"

	"github.com/notaryproject/notation-go/internal/crypto/pki"
)

// Response is a time-stamping response.
// TimeStampResp ::= SEQUENCE {
//  status          PKIStatusInfo,
//  timeStampToken  TimeStampToken  OPTIONAL }
type Response struct {
	Status         pki.StatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// MarshalBinary encodes the response to binary form.
// This method implements encoding.BinaryMarshaler
func (r *Response) MarshalBinary() ([]byte, error) {
	if r == nil {
		return nil, errors.New("nil response")
	}
	return asn1.Marshal(r)
}

// UnmarshalBinary decodes the response from binary form.
// This method implements encoding.BinaryUnmarshaler
func (r *Response) UnmarshalBinary(data []byte) error {
	_, err := asn1.Unmarshal(data, r)
	return err
}

// TokenBytes returns the bytes of the timestamp token.
func (r *Response) TokenBytes() []byte {
	return r.TimeStampToken.FullBytes
}

// SignedToken returns the timestamp token with signatures.
// Callers should invoke Verify to verify the content before comsumption.
func (r *Response) SignedToken() (*SignedToken, error) {
	return ParseSignedToken(r.TokenBytes())
}
