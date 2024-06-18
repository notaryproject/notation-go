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
	"os"
	"testing"

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
	// valid JWS signature envelope with timestamp countersignature
	jwsEnvContent, err := parseEnvContent("testdata/timestamp/jwsSigEnvWithTimestamp.sig", jws.MediaTypeEnvelope)
	if err != nil {
		t.Fatalf("failed to get signature envelope content: %v", err)
	}

	// valid COSE signature envelope with timestamp countersignature
	coseEnvContent, err := parseEnvContent("testdata/timestamp/coseSigEnvWithTimestamp.sig", cose.MediaTypeEnvelope)
	if err != nil {
		t.Fatalf("failed to get signature envelope content: %v", err)
	}

	t.Run("verify Authentic Timestamp with jws format", func(t *testing.T) {
		outcome := &notation.VerificationOutcome{
			EnvelopeContent:   jwsEnvContent,
			VerificationLevel: trustpolicy.LevelStrict,
		}
		authenticTimestampResult := verifyAuthenticTimestamp(context.Background(), dummyTrustPolicy, trustStore, outcome)
		if err := authenticTimestampResult.Error; err != nil {
			t.Fatalf("expected nil error, but got %s", err)
		}
	})

	t.Run("verify Authentic Timestamp with cose format", func(t *testing.T) {
		outcome := &notation.VerificationOutcome{
			EnvelopeContent:   coseEnvContent,
			VerificationLevel: trustpolicy.LevelStrict,
		}
		authenticTimestampResult := verifyAuthenticTimestamp(context.Background(), dummyTrustPolicy, trustStore, outcome)
		if err := authenticTimestampResult.Error; err != nil {
			t.Fatalf("expected nil error, but got %s", err)
		}
	})

	t.Run("verify Authentic Timestamp jws with expired codeSigning cert", func(t *testing.T) {
		jwsEnvContent, err := parseEnvContent("testdata/timestamp/jwsSigEnvExpiredWithTimestamp.sig", jws.MediaTypeEnvelope)
		if err != nil {
			t.Fatalf("failed to get signature envelope content: %v", err)
		}
		outcome := &notation.VerificationOutcome{
			EnvelopeContent:   jwsEnvContent,
			VerificationLevel: trustpolicy.LevelStrict,
		}
		authenticTimestampResult := verifyAuthenticTimestamp(context.Background(), dummyTrustPolicy, trustStore, outcome)
		if err := authenticTimestampResult.Error; err != nil {
			t.Fatalf("expected nil error, but got %s", err)
		}
	})

	t.Run("verify Authentic Timestamp cose with expired codeSigning cert", func(t *testing.T) {
		coseEnvContent, err := parseEnvContent("testdata/timestamp/coseSigEnvExpiredWithTimestamp.sig", cose.MediaTypeEnvelope)
		if err != nil {
			t.Fatalf("failed to get signature envelope content: %v", err)
		}
		outcome := &notation.VerificationOutcome{
			EnvelopeContent:   coseEnvContent,
			VerificationLevel: trustpolicy.LevelStrict,
		}
		authenticTimestampResult := verifyAuthenticTimestamp(context.Background(), dummyTrustPolicy, trustStore, outcome)
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
		authenticTimestampResult := verifyAuthenticTimestamp(context.Background(), dummyTrustPolicy, trustStore, outcome)
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
		authenticTimestampResult := verifyAuthenticTimestamp(context.Background(), dummyTrustPolicy, trustStore, outcome)
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
		coseEnvContent, err := parseEnvContent("testdata/timestamp/coseSigEnvExpiredWithTimestamp.sig", cose.MediaTypeEnvelope)
		if err != nil {
			t.Fatalf("failed to get signature envelope content: %v", err)
		}
		outcome := &notation.VerificationOutcome{
			EnvelopeContent:   coseEnvContent,
			VerificationLevel: trustpolicy.LevelStrict,
		}
		authenticTimestampResult := verifyAuthenticTimestamp(context.Background(), dummyTrustPolicy, trustStore, outcome)
		expectedErrMsg := "verification time is after certificate \"CN=testTSA,O=Notary,L=Seattle,ST=WA,C=US\" validity period, it was expired at \"Tue, 18 Jun 2024 07:30:31 +0000\""
		if err := authenticTimestampResult.Error; err == nil || err.Error() != expectedErrMsg {
			t.Fatalf("expected %s, but got %s", expectedErrMsg, err)
		}
	})

	t.Run("verify Authentic Timestamp failed due to missing timestamp countersignature", func(t *testing.T) {
		envContent, err := parseEnvContent("testdata/timestamp/sigEnvWithoutTimestamp.sig", jws.MediaTypeEnvelope)
		if err != nil {
			t.Fatalf("failed to get signature envelope content: %v", err)
		}
		outcome := &notation.VerificationOutcome{
			EnvelopeContent:   envContent,
			VerificationLevel: trustpolicy.LevelStrict,
		}
		authenticTimestampResult := verifyAuthenticTimestamp(context.Background(), dummyTrustPolicy, trustStore, outcome)
		expectedErrMsg := "no timestamp countersignature was found in the signature envelope"
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
