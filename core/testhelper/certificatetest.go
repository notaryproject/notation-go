package testhelper

import (
	"crypto/rsa"

	"github.com/notaryproject/notation-core-go/testhelper"
)

type RSACertTuple = testhelper.RSACertTuple

// GetRSACertTupleWithPK returns a RSACertTuple given private key.
func GetRSACertTupleWithPK(privKey *rsa.PrivateKey, cn string, issuer *RSACertTuple) RSACertTuple {
	return testhelper.GetRSACertTupleWithPK(privKey, cn, issuer)
}

// GetRSASelfSignedCertTupleWithPK returns a self-signed RSACertTuple.
func GetRSASelfSignedCertTupleWithPK(privKey *rsa.PrivateKey, cn string) RSACertTuple {
	return testhelper.GetRSASelfSignedCertTupleWithPK(privKey, cn)
}
