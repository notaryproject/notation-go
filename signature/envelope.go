package signature

import (
	"errors"

	"github.com/notaryproject/notation-core-go/signature/cose"
	"github.com/notaryproject/notation-core-go/signature/jws"
	gcose "github.com/veraison/go-cose"
)

// TODO: need inspect
// don't know how to get envelope format if passed a local signature file
// or verify with local signature
// need a better way to inspect
func GuessSignatureEnvelopeFormat(raw []byte) (string, error) {
	var msg gcose.Sign1Message
	if err := msg.UnmarshalCBOR(raw); err == nil {
		return cose.MediaTypeEnvelope, nil
	}
	if len(raw) == 0 || raw[0] != '{' {
		// very certain
		return "", errors.New("unsupported signature format")
	}
	return jws.MediaTypeEnvelope, nil
}
