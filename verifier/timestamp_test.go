// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package verifier

import (
	"context"
	"crypto/x509"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/revocation"
	"github.com/notaryproject/notation-core-go/revocation/purpose"
	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/signature/cose"
	"github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
)

func TestAuthenticTimestamp(t *testing.T) {
	dir.UserConfigDir = "testdata"
	trustStore := truststore.NewX509TrustStore(dir.ConfigFS())
	dummyTrustPolicy := &trustpolicy.TrustPolicy{
		Name:           "test-timestamp",
		RegistryScopes: []string{"*"},
		SignatureVerification: trustpolicy.SignatureVerification{
			VerificationLevel: trustpolicy.LevelStrict.Name,
			VerifyTimestamp:   trustpolicy.OptionAlways,
		},
		TrustStores:       []string{"ca:valid-trust-store", "tsa:test-timestamp"},
		TrustedIdentities: []string{"*"},
	}
	revocationTimestampingValidator, err := revocation.NewWithOptions(revocation.Options{
		OCSPHTTPClient:   &http.Client{Timeout: 2 * time.Second},
		CertChainPurpose: purpose.Timestamping,
	})
	if err != nil {
		t.Fatalf("failed to get revocation timestamp client: %v", err)
	}
	// valid JWS signature envelope with timestamp countersignature
	jwsEnvContent, err := parseEnvContent("testdata/timestamp/sigEnv/jwsWithTimestamp.sig", jws.MediaTypeEnvelope)
	if err != nil {
		t.Fatalf("failed to get signature envelope content: %v", err)
	}

	// valid COSE signature envelope with timestamp countersignature
	coseEnvContent, err := parseEnvContent("testdata/timestamp/sigEnv/coseWithTimestamp.sig", cose.MediaTypeEnvelope)
	if err != nil {
		t.Fatalf("failed to get signature envelope content: %v", err)
	}

	t.Run("verify Authentic Timestamp with jws format", func(t *testing.T) {
		outcome := &notation.VerificationOutcome{
			EnvelopeContent:   jwsEnvContent,
			VerificationLevel: trustpolicy.LevelStrict,
		}
		authenticTimestampResult := verifyAuthenticTimestamp(context.Background(), dummyTrustPolicy.Name, dummyTrustPolicy.TrustStores, dummyTrustPolicy.SignatureVerification, trustStore, revocationTimestampingValidator, outcome)
		if err := authenticTimestampResult.Error; err != nil {
			t.Fatalf("expected nil error, but got %s", err)
		}
	})

	t.Run("verify Authentic Timestamp with cose format", func(t *testing.T) {
		outcome := &notation.VerificationOutcome{
			EnvelopeContent:   coseEnvContent,
			VerificationLevel: trustpolicy.LevelStrict,
		}
		authenticTimestampResult := verifyAuthenticTimestamp(context.Background(), dummyTrustPolicy.Name, dummyTrustPolicy.TrustStores, dummyTrustPolicy.SignatureVerification, trustStore, revocationTimestampingValidator, outcome)
		if err := authenticTimestampResult.Error; err != nil {
			t.Fatalf("expected nil error, but got %s", err)
		}
	})

	t.Run("verify Authentic Timestamp jws with expired codeSigning cert", func(t *testing.T) {
		jwsEnvContent, err := parseEnvContent("testdata/timestamp/sigEnv/jwsExpiredWithTimestamp.sig", jws.MediaTypeEnvelope)
		if err != nil {
			t.Fatalf("failed to get signature envelope content: %v", err)
		}
		outcome := &notation.VerificationOutcome{
			EnvelopeContent:   jwsEnvContent,
			VerificationLevel: trustpolicy.LevelStrict,
		}
		authenticTimestampResult := verifyAuthenticTimestamp(context.Background(), dummyTrustPolicy.Name, dummyTrustPolicy.TrustStores, dummyTrustPolicy.SignatureVerification, trustStore, revocationTimestampingValidator, outcome)
		if err := authenticTimestampResult.Error; err != nil {
			t.Fatalf("expected nil error, but got %s", err)
		}
	})

	t.Run("verify Authentic Timestamp cose with expired codeSigning cert", func(t *testing.T) {
		coseEnvContent, err := parseEnvContent("testdata/timestamp/sigEnv/coseExpiredWithTimestamp.sig", cose.MediaTypeEnvelope)
		if err != nil {
			t.Fatalf("failed to get signature envelope content: %v", err)
		}
		outcome := &notation.VerificationOutcome{
			EnvelopeContent:   coseEnvContent,
			VerificationLevel: trustpolicy.LevelStrict,
		}
		authenticTimestampResult := verifyAuthenticTimestamp(context.Background(), dummyTrustPolicy.Name, dummyTrustPolicy.TrustStores, dummyTrustPolicy.SignatureVerification, trustStore, revocationTimestampingValidator, outcome)
		if err := authenticTimestampResult.Error; err != nil {
			t.Fatalf("expected nil error, but got %s", err)
		}
	})

	t.Run("verify Authentic Timestamp with afterCertExpiry set", func(t *testing.T) {
		dummyTrustPolicy := &trustpolicy.TrustPolicy{
			Name:           "test-timestamp",
			RegistryScopes: []string{"*"},
			SignatureVerification: trustpolicy.SignatureVerification{
				VerificationLevel: trustpolicy.LevelStrict.Name,
				VerifyTimestamp:   trustpolicy.OptionAfterCertExpiry,
			},
			TrustStores:       []string{"ca:valid-trust-store", "tsa:test-timestamp"},
			TrustedIdentities: []string{"*"},
		}
		outcome := &notation.VerificationOutcome{
			EnvelopeContent:   coseEnvContent,
			VerificationLevel: trustpolicy.LevelStrict,
		}
		authenticTimestampResult := verifyAuthenticTimestamp(context.Background(), dummyTrustPolicy.Name, dummyTrustPolicy.TrustStores, dummyTrustPolicy.SignatureVerification, trustStore, revocationTimestampingValidator, outcome)
		if err := authenticTimestampResult.Error; err != nil {
			t.Fatalf("expected nil error, but got %s", err)
		}
	})

	t.Run("verify Authentic Timestamp failed due to invalid trust policy", func(t *testing.T) {
		dummyTrustPolicy := &trustpolicy.TrustPolicy{
			Name:           "test-timestamp",
			RegistryScopes: []string{"*"},
			SignatureVerification: trustpolicy.SignatureVerification{
				VerificationLevel: trustpolicy.LevelStrict.Name,
				VerifyTimestamp:   trustpolicy.OptionAlways,
			},
			TrustStores:       []string{"ca:valid-trust-store", "tsa"},
			TrustedIdentities: []string{"*"},
		}
		outcome := &notation.VerificationOutcome{
			EnvelopeContent:   jwsEnvContent,
			VerificationLevel: trustpolicy.LevelStrict,
		}
		authenticTimestampResult := verifyAuthenticTimestamp(context.Background(), dummyTrustPolicy.Name, dummyTrustPolicy.TrustStores, dummyTrustPolicy.SignatureVerification, trustStore, revocationTimestampingValidator, outcome)
		expectedErrMsg := "failed to check tsa trust store configuration in turst policy with error: invalid trust policy statement: \"test-timestamp\" is missing separator in trust store value \"tsa\". The required format is <TrustStoreType>:<TrustStoreName>"
		if err := authenticTimestampResult.Error; err == nil || err.Error() != expectedErrMsg {
			t.Fatalf("expected %s, but got %s", expectedErrMsg, err)
		}
	})

	t.Run("verify Authentic Timestamp failed due to missing tsa in trust policy and expired codeSigning cert", func(t *testing.T) {
		dummyTrustPolicy := &trustpolicy.TrustPolicy{
			Name:           "test-timestamp",
			RegistryScopes: []string{"*"},
			SignatureVerification: trustpolicy.SignatureVerification{
				VerificationLevel: trustpolicy.LevelStrict.Name,
				VerifyTimestamp:   trustpolicy.OptionAlways,
			},
			TrustStores:       []string{"ca:valid-trust-store"},
			TrustedIdentities: []string{"*"},
		}
		coseEnvContent, err := parseEnvContent("testdata/timestamp/sigEnv/coseExpiredWithTimestamp.sig", cose.MediaTypeEnvelope)
		if err != nil {
			t.Fatalf("failed to get signature envelope content: %v", err)
		}
		outcome := &notation.VerificationOutcome{
			EnvelopeContent:   coseEnvContent,
			VerificationLevel: trustpolicy.LevelStrict,
		}
		authenticTimestampResult := verifyAuthenticTimestamp(context.Background(), dummyTrustPolicy.Name, dummyTrustPolicy.TrustStores, dummyTrustPolicy.SignatureVerification, trustStore, revocationTimestampingValidator, outcome)
		expectedErrMsg := "verification time is after certificate \"CN=testTSA,O=Notary,L=Seattle,ST=WA,C=US\" validity period, it was expired at \"Tue, 18 Jun 2024 07:30:31 +0000\""
		if err := authenticTimestampResult.Error; err == nil || err.Error() != expectedErrMsg {
			t.Fatalf("expected %s, but got %s", expectedErrMsg, err)
		}
	})

	t.Run("verify Authentic Timestamp failed due to missing timestamp countersignature", func(t *testing.T) {
		envContent, err := parseEnvContent("testdata/timestamp/sigEnv/withoutTimestamp.sig", jws.MediaTypeEnvelope)
		if err != nil {
			t.Fatalf("failed to get signature envelope content: %v", err)
		}
		outcome := &notation.VerificationOutcome{
			EnvelopeContent:   envContent,
			VerificationLevel: trustpolicy.LevelStrict,
		}
		authenticTimestampResult := verifyAuthenticTimestamp(context.Background(), dummyTrustPolicy.Name, dummyTrustPolicy.TrustStores, dummyTrustPolicy.SignatureVerification, trustStore, revocationTimestampingValidator, outcome)
		expectedErrMsg := "no timestamp countersignature was found in the signature envelope"
		if err := authenticTimestampResult.Error; err == nil || err.Error() != expectedErrMsg {
			t.Fatalf("expected %s, but got %s", expectedErrMsg, err)
		}
	})

	t.Run("verify Authentic Timestamp failed due to invalid timestamp countersignature content type", func(t *testing.T) {
		signedToken, err := os.ReadFile("testdata/timestamp/countersignature/TimeStampTokenWithInvalideContentType.p7s")
		if err != nil {
			t.Fatalf("failed to get signedToken: %v", err)
		}
		envContent, err := parseEnvContent("testdata/timestamp/sigEnv/withoutTimestamp.sig", jws.MediaTypeEnvelope)
		if err != nil {
			t.Fatalf("failed to get signature envelope content: %v", err)
		}
		envContent.SignerInfo.UnsignedAttributes.TimestampSignature = signedToken
		outcome := &notation.VerificationOutcome{
			EnvelopeContent:   envContent,
			VerificationLevel: trustpolicy.LevelStrict,
		}
		authenticTimestampResult := verifyAuthenticTimestamp(context.Background(), dummyTrustPolicy.Name, dummyTrustPolicy.TrustStores, dummyTrustPolicy.SignatureVerification, trustStore, revocationTimestampingValidator, outcome)
		expectedErrMsg := "failed to parse timestamp countersignature with error: unexpected content type: 1.2.840.113549.1.7.1. Expected to be id-ct-TSTInfo (1.2.840.113549.1.9.16.1.4)"
		if err := authenticTimestampResult.Error; err == nil || err.Error() != expectedErrMsg {
			t.Fatalf("expected %s, but got %s", expectedErrMsg, err)
		}
	})

	t.Run("verify Authentic Timestamp failed due to invalid TSTInfo", func(t *testing.T) {
		signedToken, err := os.ReadFile("testdata/timestamp/countersignature/TimeStampTokenWithInvalidTSTInfo.p7s")
		if err != nil {
			t.Fatalf("failed to get signedToken: %v", err)
		}
		envContent, err := parseEnvContent("testdata/timestamp/sigEnv/withoutTimestamp.sig", jws.MediaTypeEnvelope)
		if err != nil {
			t.Fatalf("failed to get signature envelope content: %v", err)
		}
		envContent.SignerInfo.UnsignedAttributes.TimestampSignature = signedToken
		outcome := &notation.VerificationOutcome{
			EnvelopeContent:   envContent,
			VerificationLevel: trustpolicy.LevelStrict,
		}
		authenticTimestampResult := verifyAuthenticTimestamp(context.Background(), dummyTrustPolicy.Name, dummyTrustPolicy.TrustStores, dummyTrustPolicy.SignatureVerification, trustStore, revocationTimestampingValidator, outcome)
		expectedErrMsg := "failed to get the timestamp TSTInfo with error: cannot unmarshal TSTInfo from timestamp token: asn1: structure error: tags don't match (23 vs {class:0 tag:16 length:3 isCompound:true}) {optional:false explicit:false application:false private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:24 set:false omitEmpty:false} Time @89"
		if err := authenticTimestampResult.Error; err == nil || err.Error() != expectedErrMsg {
			t.Fatalf("expected %s, but got %s", expectedErrMsg, err)
		}
	})

	t.Run("verify Authentic Timestamp failed due to failed to validate TSTInfo", func(t *testing.T) {
		signedToken, err := os.ReadFile("testdata/timestamp/countersignature/TimeStampToken.p7s")
		if err != nil {
			t.Fatalf("failed to get signedToken: %v", err)
		}
		envContent, err := parseEnvContent("testdata/timestamp/sigEnv/withoutTimestamp.sig", jws.MediaTypeEnvelope)
		if err != nil {
			t.Fatalf("failed to get signature envelope content: %v", err)
		}
		envContent.SignerInfo.UnsignedAttributes.TimestampSignature = signedToken
		envContent.SignerInfo.Signature = []byte("mismatch")
		outcome := &notation.VerificationOutcome{
			EnvelopeContent:   envContent,
			VerificationLevel: trustpolicy.LevelStrict,
		}
		authenticTimestampResult := verifyAuthenticTimestamp(context.Background(), dummyTrustPolicy.Name, dummyTrustPolicy.TrustStores, dummyTrustPolicy.SignatureVerification, trustStore, revocationTimestampingValidator, outcome)
		expectedErrMsg := "failed to get timestamp from timestamp countersignature with error: invalid TSTInfo: mismatched message"
		if err := authenticTimestampResult.Error; err == nil || err.Error() != expectedErrMsg {
			t.Fatalf("expected %s, but got %s", expectedErrMsg, err)
		}
	})

	t.Run("verify Authentic Timestamp failed due to failed to verify timestamp countersignature", func(t *testing.T) {
		signedToken, err := os.ReadFile("testdata/timestamp/countersignature/TimeStampTokenWithoutCertificate.p7s")
		if err != nil {
			t.Fatalf("failed to get signedToken: %v", err)
		}
		envContent, err := parseEnvContent("testdata/timestamp/sigEnv/withoutTimestamp.sig", jws.MediaTypeEnvelope)
		if err != nil {
			t.Fatalf("failed to get signature envelope content: %v", err)
		}
		envContent.SignerInfo.UnsignedAttributes.TimestampSignature = signedToken
		envContent.SignerInfo.Signature = []byte("notation")
		outcome := &notation.VerificationOutcome{
			EnvelopeContent:   envContent,
			VerificationLevel: trustpolicy.LevelStrict,
		}
		authenticTimestampResult := verifyAuthenticTimestamp(context.Background(), dummyTrustPolicy.Name, dummyTrustPolicy.TrustStores, dummyTrustPolicy.SignatureVerification, trustStore, revocationTimestampingValidator, outcome)
		expectedErrMsg := "failed to verify the timestamp countersignature with error: failed to verify signed token: signing certificate not found in the timestamp token"
		if err := authenticTimestampResult.Error; err == nil || err.Error() != expectedErrMsg {
			t.Fatalf("expected %s, but got %s", expectedErrMsg, err)
		}
	})

	t.Run("verify Authentic Timestamp failed due to signing time after timestamp value", func(t *testing.T) {
		signedToken, err := os.ReadFile("testdata/timestamp/countersignature/TimeStampToken.p7s")
		if err != nil {
			t.Fatalf("failed to get signedToken: %v", err)
		}
		envContent, err := parseEnvContent("testdata/timestamp/sigEnv/withoutTimestamp.sig", jws.MediaTypeEnvelope)
		if err != nil {
			t.Fatalf("failed to get signature envelope content: %v", err)
		}
		envContent.SignerInfo.UnsignedAttributes.TimestampSignature = signedToken
		envContent.SignerInfo.Signature = []byte("notation")
		envContent.SignerInfo.SignedAttributes.SigningTime = time.Date(3000, time.November, 10, 23, 0, 0, 0, time.UTC)
		outcome := &notation.VerificationOutcome{
			EnvelopeContent:   envContent,
			VerificationLevel: trustpolicy.LevelStrict,
		}
		authenticTimestampResult := verifyAuthenticTimestamp(context.Background(), dummyTrustPolicy.Name, dummyTrustPolicy.TrustStores, dummyTrustPolicy.SignatureVerification, trustStore, revocationTimestampingValidator, outcome)
		expectedErrMsg := "timestamp [2021-09-17T14:09:09Z, 2021-09-17T14:09:11Z] is not bounded after the signing time \"3000-11-10 23:00:00 +0000 UTC\""
		if err := authenticTimestampResult.Error; err == nil || err.Error() != expectedErrMsg {
			t.Fatalf("expected %s, but got %s", expectedErrMsg, err)
		}
	})

	t.Run("verify Authentic Timestamp failed due to trust store does not exist", func(t *testing.T) {
		dummyTrustPolicy := &trustpolicy.TrustPolicy{
			Name:           "test-timestamp",
			RegistryScopes: []string{"*"},
			SignatureVerification: trustpolicy.SignatureVerification{
				VerificationLevel: trustpolicy.LevelStrict.Name,
				VerifyTimestamp:   trustpolicy.OptionAlways,
			},
			TrustStores:       []string{"ca:valid-trust-store", "tsa:does-not-exist"},
			TrustedIdentities: []string{"*"},
		}
		outcome := &notation.VerificationOutcome{
			EnvelopeContent:   coseEnvContent,
			VerificationLevel: trustpolicy.LevelStrict,
		}
		authenticTimestampResult := verifyAuthenticTimestamp(context.Background(), dummyTrustPolicy.Name, dummyTrustPolicy.TrustStores, dummyTrustPolicy.SignatureVerification, trustStore, revocationTimestampingValidator, outcome)
		expectedErrMsg := "failed to load tsa trust store with error: the trust store \"does-not-exist\" of type \"tsa\" does not exist"
		if err := authenticTimestampResult.Error; err == nil || err.Error() != expectedErrMsg {
			t.Fatalf("expected %s, but got %s", expectedErrMsg, err)
		}
	})

	t.Run("verify Authentic Timestamp failed due to empty trust store", func(t *testing.T) {
		dummyTrustPolicy := &trustpolicy.TrustPolicy{
			Name:           "test-timestamp",
			RegistryScopes: []string{"*"},
			SignatureVerification: trustpolicy.SignatureVerification{
				VerificationLevel: trustpolicy.LevelStrict.Name,
				VerifyTimestamp:   trustpolicy.OptionAlways,
			},
			TrustStores:       []string{"ca:valid-trust-store", "tsa:test-empty"},
			TrustedIdentities: []string{"*"},
		}
		outcome := &notation.VerificationOutcome{
			EnvelopeContent:   coseEnvContent,
			VerificationLevel: trustpolicy.LevelStrict,
		}
		authenticTimestampResult := verifyAuthenticTimestamp(context.Background(), dummyTrustPolicy.Name, dummyTrustPolicy.TrustStores, dummyTrustPolicy.SignatureVerification, dummyTrustStore{}, revocationTimestampingValidator, outcome)
		expectedErrMsg := "no trusted TSA certificate found in trust store"
		if err := authenticTimestampResult.Error; err == nil || err.Error() != expectedErrMsg {
			t.Fatalf("expected %s, but got %s", expectedErrMsg, err)
		}
	})

	t.Run("verify Authentic Timestamp failed due to tsa not trust", func(t *testing.T) {
		dummyTrustPolicy := &trustpolicy.TrustPolicy{
			Name:           "test-timestamp",
			RegistryScopes: []string{"*"},
			SignatureVerification: trustpolicy.SignatureVerification{
				VerificationLevel: trustpolicy.LevelStrict.Name,
				VerifyTimestamp:   trustpolicy.OptionAlways,
			},
			TrustStores:       []string{"ca:valid-trust-store", "tsa:test-mismatch"},
			TrustedIdentities: []string{"*"},
		}
		outcome := &notation.VerificationOutcome{
			EnvelopeContent:   coseEnvContent,
			VerificationLevel: trustpolicy.LevelStrict,
		}
		authenticTimestampResult := verifyAuthenticTimestamp(context.Background(), dummyTrustPolicy.Name, dummyTrustPolicy.TrustStores, dummyTrustPolicy.SignatureVerification, trustStore, revocationTimestampingValidator, outcome)
		expectedErrMsg := "failed to verify the timestamp countersignature with error: failed to verify signed token: cms verification failure: x509: certificate signed by unknown authority"
		if err := authenticTimestampResult.Error; err == nil || err.Error() != expectedErrMsg {
			t.Fatalf("expected %s, but got %s", expectedErrMsg, err)
		}
	})

	t.Run("verify Authentic Timestamp failed due to timestamp before signing cert not before", func(t *testing.T) {
		dummyTrustPolicy := &trustpolicy.TrustPolicy{
			Name:           "test-timestamp",
			RegistryScopes: []string{"*"},
			SignatureVerification: trustpolicy.SignatureVerification{
				VerificationLevel: trustpolicy.LevelStrict.Name,
				VerifyTimestamp:   trustpolicy.OptionAlways,
			},
			TrustStores:       []string{"ca:valid-trust-store", "tsa:test-timestamp"},
			TrustedIdentities: []string{"*"},
		}
		envContent, err := parseEnvContent("testdata/timestamp/sigEnv/timestampBeforeNotBefore.sig", jws.MediaTypeEnvelope)
		if err != nil {
			t.Fatalf("failed to get signature envelope content: %v", err)
		}
		outcome := &notation.VerificationOutcome{
			EnvelopeContent:   envContent,
			VerificationLevel: trustpolicy.LevelStrict,
		}
		authenticTimestampResult := verifyAuthenticTimestamp(context.Background(), dummyTrustPolicy.Name, dummyTrustPolicy.TrustStores, dummyTrustPolicy.SignatureVerification, trustStore, revocationTimestampingValidator, outcome)
		expectedErrMsg := "timestamp can be before certificate \"CN=testTSA,O=Notary,L=Seattle,ST=WA,C=US\" validity period, it will be valid from \"Fri, 18 Sep 2099 11:54:34 +0000\""
		if err := authenticTimestampResult.Error; err == nil || err.Error() != expectedErrMsg {
			t.Fatalf("expected %s, but got %s", expectedErrMsg, err)
		}
	})

	t.Run("verify Authentic Timestamp failed due to timestamp after signing cert not after", func(t *testing.T) {
		dummyTrustPolicy := &trustpolicy.TrustPolicy{
			Name:           "test-timestamp",
			RegistryScopes: []string{"*"},
			SignatureVerification: trustpolicy.SignatureVerification{
				VerificationLevel: trustpolicy.LevelStrict.Name,
				VerifyTimestamp:   trustpolicy.OptionAlways,
			},
			TrustStores:       []string{"ca:valid-trust-store", "tsa:test-timestamp"},
			TrustedIdentities: []string{"*"},
		}
		envContent, err := parseEnvContent("testdata/timestamp/sigEnv/timestampAfterNotAfter.sig", cose.MediaTypeEnvelope)
		if err != nil {
			t.Fatalf("failed to get signature envelope content: %v", err)
		}
		outcome := &notation.VerificationOutcome{
			EnvelopeContent:   envContent,
			VerificationLevel: trustpolicy.LevelStrict,
		}
		authenticTimestampResult := verifyAuthenticTimestamp(context.Background(), dummyTrustPolicy.Name, dummyTrustPolicy.TrustStores, dummyTrustPolicy.SignatureVerification, trustStore, revocationTimestampingValidator, outcome)
		expectedErrMsg := "timestamp can be after certificate \"CN=testTSA,O=Notary,L=Seattle,ST=WA,C=US\" validity period, it was expired at \"Tue, 18 Sep 2001 11:54:34 +0000\""
		if err := authenticTimestampResult.Error; err == nil || err.Error() != expectedErrMsg {
			t.Fatalf("expected %s, but got %s", expectedErrMsg, err)
		}
	})
}

func parseEnvContent(filepath, format string) (*signature.EnvelopeContent, error) {
	sigEnvBytes, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	sigEnv, err := signature.ParseEnvelope(format, sigEnvBytes)
	if err != nil {
		return nil, err
	}
	return sigEnv.Content()
}

type dummyTrustStore struct{}

func (ts dummyTrustStore) GetCertificates(ctx context.Context, storeType truststore.Type, namedStore string) ([]*x509.Certificate, error) {
	return nil, nil
}
