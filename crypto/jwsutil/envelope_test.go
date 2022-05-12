package jwsutil

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestEnvelope_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		data string
		want Envelope
	}{
		{
			name: "General JWS JSON Serialization Syntax (multiple signatures)",
			data: `{
				"payload": "test payload",
				"signatures": [
					{
						"protected": "protected foo",
						"header": {"unprotected": "foo"},
						"signature": "signature foo"
					},
					{
						"protected": "protected bar",
						"header": {"unprotected": "bar"},
						"signature": "signature bar"
					}
				]
			}`,
			want: Envelope{
				Payload: "test payload",
				Signatures: []Signature{
					{
						Protected:   "protected foo",
						Unprotected: []byte(`{"unprotected": "foo"}`),
						Signature:   "signature foo",
					},
					{
						Protected:   "protected bar",
						Unprotected: []byte(`{"unprotected": "bar"}`),
						Signature:   "signature bar",
					},
				},
			},
		},
		{
			name: "General JWS JSON Serialization Syntax (single signature)",
			data: `{
				"payload": "test payload",
				"signatures": [
					{
						"protected": "protected foo",
						"header": {"unprotected": "foo"},
						"signature": "signature foo"
					}
				]
			}`,
			want: Envelope{
				Payload: "test payload",
				Signatures: []Signature{
					{
						Protected:   "protected foo",
						Unprotected: []byte(`{"unprotected": "foo"}`),
						Signature:   "signature foo",
					},
				},
			},
		},
		{
			name: "Flattened JWS JSON Serialization Syntax",
			data: `{
				"payload": "test payload",
				"protected": "protected foo",
				"header": {"unprotected": "foo"},
				"signature": "signature foo"
			}`,
			want: Envelope{
				Payload: "test payload",
				Signatures: []Signature{
					{
						Protected:   "protected foo",
						Unprotected: []byte(`{"unprotected": "foo"}`),
						Signature:   "signature foo",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Envelope
			if err := json.Unmarshal([]byte(tt.data), &got); err != nil {
				t.Fatalf("Envelope.UnmarshalJSON() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Envelope.UnmarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}
