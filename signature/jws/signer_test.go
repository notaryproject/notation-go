package jws

import (
	"testing"

	"github.com/notaryproject/notation-go-lib"
)

func TestSignerInterface(t *testing.T) {
	if _, ok := interface{}(&Signer{}).(notation.Signer); !ok {
		t.Error("&Signer{} does not conform notation.Signer")
	}
}
