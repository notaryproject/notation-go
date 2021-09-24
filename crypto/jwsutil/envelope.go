package jwsutil

import "encoding/json"

// Envelope contains a common payload signed by multiple signatures.
type Envelope struct {
	Payload    string      `json:"payload,omitempty"`
	Signatures []Signature `json:"signatures,omitempty"`
}

// Size returns the number of enclosed signatures.
func (e Envelope) Size() int {
	return len(e.Signatures)
}

// Open opens the evelope and returns the first or default complete signature.
func (e Envelope) Open() CompleteSignature {
	if len(e.Signatures) == 0 {
		return CompleteSignature{
			Payload: e.Payload,
		}
	}
	return CompleteSignature{
		Payload:   e.Payload,
		Signature: e.Signatures[0],
	}
}

// UnmarshalJSON parses the JSON serialized JWS.
// Reference: RFC 7515 7.2 JWS JSON Serialization.
func (e *Envelope) UnmarshalJSON(data []byte) error {
	var combined struct {
		CompleteSignature
		Signatures []Signature `json:"signatures"`
	}
	if err := json.Unmarshal(data, &combined); err != nil {
		return ErrInvalidJSONSerialization
	}
	if len(combined.Signatures) == 0 {
		*e = Envelope{
			Payload: combined.Payload,
			Signatures: []Signature{
				combined.Signature,
			},
		}
	} else {
		*e = Envelope{
			Payload:    combined.Payload,
			Signatures: combined.Signatures,
		}
	}
	return nil
}
