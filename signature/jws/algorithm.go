package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/notaryproject/notation-go"
)

func keySpecFromKey(key interface{}) (notation.KeySpec, error) {
	if k, ok := key.(interface {
		Public() crypto.PublicKey
	}); ok {
		key = k.Public()
	}

	switch key := key.(type) {
	case *rsa.PublicKey:
		switch size := key.Size(); size {
		case 256:
			return notation.RSA_2048, nil
		case 384:
			return notation.RSA_3072, nil
		case 512:
			return notation.RSA_4096, nil
		default:
			return "", fmt.Errorf("RSA key of size %q bits is not supported", key.N.BitLen())
		}
	case *ecdsa.PublicKey:
		params := key.Curve.Params()
		switch size := params.N.BitLen(); size {
		case 256:
			return notation.EC_256, nil
		case 384:
			return notation.EC_384, nil
		case 521:
			return notation.EC_512, nil
		default:
			return "", fmt.Errorf("EC key %q of size %q bits is not supported", params.Name, size)
		}
	}
	return "", errors.New("unsupported key type, only RSA and EC keys are supported")
}
