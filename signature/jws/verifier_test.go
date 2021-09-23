package jws

import (
	"testing"

	"github.com/notaryproject/notation-go-lib"
)

func TestVerifierInterface(t *testing.T) {
	if _, ok := interface{}(&Verifier{}).(notation.Verifier); !ok {
		t.Error("&Verifier{} does not conform notation.Verifier")
	}
}
