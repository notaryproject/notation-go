// Package timestamptest provides utilities for timestamp testing
package timestamptest

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math"
	"math/big"
	"time"

	"github.com/notaryproject/notation-go/crypto/timestamp"
	"github.com/notaryproject/notation-go/internal/crypto/cms"
	"github.com/notaryproject/notation-go/internal/crypto/hashutil"
	"github.com/notaryproject/notation-go/internal/crypto/oid"
	"github.com/notaryproject/notation-go/internal/crypto/pki"
)

// responseRejection is a general response for request rejection.
var responseRejection = &timestamp.Response{
	Status: pki.StatusInfo{
		Status: pki.StatusRejection,
	},
}

// TSA is a Timestamping Authority for testing purpose.
type TSA struct {
	// key is the TSA signing key.
	key *rsa.PrivateKey

	// cert is the self-signed certificate by the TSA signing key.
	cert *x509.Certificate

	// NowFunc provides the current time. time.Now() is used if nil.
	NowFunc func() time.Time
}

// NewTSA creates a TSA with random credentials.
func NewTSA() (*TSA, error) {
	// generate key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// generate certificate
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "timestamp test",
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	return &TSA{
		key:  key,
		cert: cert,
	}, nil
}

// Certificate returns the certificate used by the server.
func (tsa *TSA) Certificate() *x509.Certificate {
	return tsa.cert
}

// Timestamp stamps the time with the given request.
func (tsa *TSA) Timestamp(_ context.Context, req *timestamp.Request) (*timestamp.Response, error) {
	// validate request
	if req.Version != 1 {
		return responseRejection, nil
	}
	hash, ok := oid.ConvertToHash(req.MessageImprint.HashAlgorithm.Algorithm)
	if !ok {
		return responseRejection, nil
	}
	if hashedMessage := req.MessageImprint.HashedMessage; len(hashedMessage) != hash.Size() {
		return responseRejection, nil
	}

	// generate token info
	policy := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 4146, 2} // time-stamp-policies
	switch hash {
	case crypto.SHA1:
		policy = append(policy, 2)
	case crypto.SHA256, crypto.SHA384, crypto.SHA512:
		policy = append(policy, 3)
	default:
		return responseRejection, nil
	}
	infoBytes, err := tsa.generateTokenInfo(req, policy)
	if err != nil {
		return nil, err
	}

	// generate signed data
	signed, err := tsa.generateSignedData(infoBytes, req.CertReq)
	if err != nil {
		return nil, err
	}
	content, err := convertToRawASN1(signed, "explicit,tag:0")
	if err != nil {
		return nil, err
	}

	// generate content info
	contentInfo := cms.ContentInfo{
		ContentType: oid.SignedData,
		Content:     content,
	}
	token, err := convertToRawASN1(contentInfo, "")
	if err != nil {
		return nil, err
	}

	// generate response
	return &timestamp.Response{
		Status: pki.StatusInfo{
			Status: pki.StatusGranted,
		},
		TimeStampToken: token,
	}, nil
}

// generateTokenInfo generate timestamp token info.
func (tsa *TSA) generateTokenInfo(req *timestamp.Request, policy asn1.ObjectIdentifier) ([]byte, error) {
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, err
	}
	nowFunc := tsa.NowFunc
	if nowFunc == nil {
		nowFunc = time.Now
	}
	info := timestamp.TSTInfo{
		Version:        1,
		Policy:         policy,
		MessageImprint: req.MessageImprint,
		SerialNumber:   serialNumber,
		GenTime:        nowFunc().UTC().Truncate(time.Second),
		Accuracy: timestamp.Accuracy{
			Seconds: 1,
		},
	}
	return asn1.Marshal(info)
}

// generateSignedData generate signed data according to
func (tsa *TSA) generateSignedData(infoBytes []byte, requestCert bool) (cms.SignedData, error) {
	var issuer asn1.RawValue
	_, err := asn1.Unmarshal(tsa.cert.RawIssuer, &issuer)
	if err != nil {
		return cms.SignedData{}, err
	}
	contentType, err := convertToRawASN1([]interface{}{oid.TSTInfo}, "set")
	if err != nil {
		return cms.SignedData{}, err
	}
	infoDigest, err := hashutil.ComputeHash(crypto.SHA256, infoBytes)
	if err != nil {
		return cms.SignedData{}, err
	}
	messageDigest, err := convertToRawASN1([]interface{}{infoDigest}, "set")
	if err != nil {
		return cms.SignedData{}, err
	}
	signingTime, err := convertToRawASN1([]interface{}{time.Now().UTC()}, "set")
	if err != nil {
		return cms.SignedData{}, err
	}
	signed := cms.SignedData{
		Version: 3,
		DigestAlgorithmIdentifiers: []pkix.AlgorithmIdentifier{
			{
				Algorithm: oid.SHA256,
			},
		},
		EncapsulatedContentInfo: cms.EncapsulatedContentInfo{
			ContentType: oid.TSTInfo,
			Content:     infoBytes,
		},
		SignerInfos: []cms.SignerInfo{
			{
				Version: 1,
				SignerIdentifier: cms.IssuerAndSerialNumber{
					Issuer:       issuer,
					SerialNumber: tsa.cert.SerialNumber,
				},
				DigestAlgorithm: pkix.AlgorithmIdentifier{
					Algorithm: oid.SHA256,
				},
				SignedAttributes: cms.Attributes{
					{
						Type:   oid.ContentType,
						Values: contentType,
					},
					{
						Type:   oid.MessageDigest,
						Values: messageDigest,
					},
					{
						Type:   oid.SigningTime,
						Values: signingTime,
					},
				},
				SignatureAlgorithm: pkix.AlgorithmIdentifier{
					Algorithm: oid.SHA256WithRSA,
				},
			},
		},
	}
	if requestCert {
		certs, err := convertToRawASN1(tsa.cert.Raw, "tag:0")
		if err != nil {
			return cms.SignedData{}, err
		}
		signed.Certificates = certs
	}

	// sign data
	signer := &signed.SignerInfos[0]
	encodedAttributes, err := asn1.MarshalWithParams(signer.SignedAttributes, "set")
	if err != nil {
		return cms.SignedData{}, err
	}
	hashedAttributes, err := hashutil.ComputeHash(crypto.SHA256, encodedAttributes)
	if err != nil {
		return cms.SignedData{}, err
	}
	signer.Signature, err = rsa.SignPKCS1v15(rand.Reader, tsa.key, crypto.SHA256, hashedAttributes)
	if err != nil {
		return cms.SignedData{}, err
	}
	return signed, nil
}

// convertToRawASN1 convert any data ASN.1 data structure to asn1.RawValue.
func convertToRawASN1(val interface{}, params string) (asn1.RawValue, error) {
	b, err := asn1.MarshalWithParams(val, params)
	if err != nil {
		return asn1.NullRawValue, err
	}
	var raw asn1.RawValue
	_, err = asn1.UnmarshalWithParams(b, &raw, params)
	if err != nil {
		return asn1.NullRawValue, err
	}
	return raw, nil
}
