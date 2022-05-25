package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
	"github.com/notaryproject/notation-go"
)

// SigningMethodFromKey picks up a recommended algorithm for private and public keys.
// Reference: RFC 7518 3.1 "alg" (Algorithm) Header Parameter Values for JWS.
func SigningMethodFromKey(key interface{}) (jwt.SigningMethod, error) {
	_, method, err := keySpecFromKey(key)
	return method, err
}

func keySpecFromKey(key interface{}) (notation.KeySpec, jwt.SigningMethod, error) {
	if k, ok := key.(interface {
		Public() crypto.PublicKey
	}); ok {
		key = k.Public()
	}

	switch key := key.(type) {
	case *rsa.PublicKey:
		switch size := key.Size(); size {
		case 256:
			return notation.RSA_2048, jwt.SigningMethodPS256, nil
		case 384:
			return notation.RSA_3072, jwt.SigningMethodPS384, nil
		case 512:
			return notation.RSA_4096, jwt.SigningMethodPS512, nil
		default:
			return "", nil, fmt.Errorf("RSA key of size %q bits is not supported", key.N.BitLen())
		}
	case *ecdsa.PublicKey:
		switch params := key.Curve.Params(); params.BitSize {
		case 256:
			return notation.EC_256, jwt.SigningMethodES256, nil
		case 384:
			return notation.EC_384, jwt.SigningMethodES384, nil
		case 521:
			return notation.EC_512, jwt.SigningMethodES512, nil
		default:
			return "", nil, fmt.Errorf("EC key %q of size %q bits is not supported", params.Name, params.BitSize)
		}
	}
	return "", nil, errors.New("unsupported key type, only RSA and EC keys are supported")
}
