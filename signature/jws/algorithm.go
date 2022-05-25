package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"

	"github.com/golang-jwt/jwt/v4"
	"github.com/notaryproject/notation-go"
)

// SigningMethodFromKey picks up a recommended algorithm for private and public keys.
// Reference: RFC 7518 3.1 "alg" (Algorithm) Header Parameter Values for JWS.
func SigningMethodFromKey(key interface{}) (jwt.SigningMethod, error) {
	if k, ok := key.(interface {
		Public() crypto.PublicKey
	}); ok {
		key = k.Public()
	}

	switch key := key.(type) {
	case *rsa.PublicKey:
		switch key.Size() {
		case 256:
			return jwt.SigningMethodPS256, nil
		case 384:
			return jwt.SigningMethodPS384, nil
		case 512:
			return jwt.SigningMethodPS512, nil
		default:
			return jwt.SigningMethodPS256, nil
		}
	case *ecdsa.PublicKey:
		switch key.Curve.Params().BitSize {
		case jwt.SigningMethodES256.CurveBits:
			return jwt.SigningMethodES256, nil
		case jwt.SigningMethodES384.CurveBits:
			return jwt.SigningMethodES384, nil
		case jwt.SigningMethodES512.CurveBits:
			return jwt.SigningMethodES512, nil
		default:
			return nil, errors.New("ecdsa key not recognized")
		}
	case *ed25519.PublicKey:
		return jwt.SigningMethodEdDSA, nil
	}
	return nil, errors.New("key not recognized")
}

func keySpecFromKey(key interface{}) (notation.KeySpec, error) {
	if k, ok := key.(interface {
		Public() crypto.PublicKey
	}); ok {
		key = k.Public()
	}

	switch key := key.(type) {
	case *rsa.PublicKey:
		switch key.Size() {
		case 256:
			return notation.RSA_2048, nil
		case 384:
			return notation.RSA_3072, nil
		case 512:
			return notation.RSA_4096, nil
		default:
			return "", fmt.Errorf("RSA key of size %q bits is not supported", key.Size()*8)
		}
	case *ecdsa.PublicKey:
		switch key.Curve.Params().BitSize {
		case jwt.SigningMethodES256.CurveBits:
			return notation.EC_256, nil
		case jwt.SigningMethodES384.CurveBits:
			return notation.EC_384, nil
		case jwt.SigningMethodES512.CurveBits:
			return notation.EC_512, nil
		default:
			return "", return fmt.Errorf("EC key %q of size %q bits is not supported", key.Curve.Params().Name, key.Curve.BitSize)
		}
	}
	return "", errors.New("unsupported key type, only RSA and EC keys are supported")
}
