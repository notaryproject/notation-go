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

// Package signer provides notation signing functionality. It implements the
// notation.Signer interface by providing builtinSigner for local signing and
// pluginSigner for remote signing.
package signer

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/internal/envelope"
	"github.com/notaryproject/notation-go/log"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// signingAgent is the unprotected header field used by signature.
const signingAgent = "notation-go/1.1.2"

// genericSigner implements notation.Signer and embeds signature.Signer
type genericSigner struct {
	signature.Signer
}

// New returns a builtinSigner given key and cert chain
func New(key crypto.PrivateKey, certChain []*x509.Certificate) (notation.Signer, error) {
	localSigner, err := signature.NewLocalSigner(certChain, key)
	if err != nil {
		return nil, err
	}
	return &genericSigner{
		Signer: localSigner,
	}, nil
}

// NewFromFiles returns a builtinSigner given key and certChain paths.
func NewFromFiles(keyPath, certChainPath string) (notation.Signer, error) {
	if keyPath == "" {
		return nil, errors.New("key path not specified")
	}
	if certChainPath == "" {
		return nil, errors.New("certificate path not specified")
	}

	// read key / cert pair
	cert, err := tls.LoadX509KeyPair(certChainPath, keyPath)
	if err != nil {
		return nil, err
	}
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("%q does not contain certificate", certChainPath)
	}

	// parse cert
	certs := make([]*x509.Certificate, len(cert.Certificate))
	for i, c := range cert.Certificate {
		certs[i], err = x509.ParseCertificate(c)
		if err != nil {
			return nil, err
		}
	}

	// create signer
	return New(cert.PrivateKey, certs)
}

// Sign signs the artifact described by its descriptor and returns the
// marshalled envelope.
func (s *genericSigner) Sign(ctx context.Context, desc ocispec.Descriptor, opts notation.SignerSignOptions) ([]byte, *signature.SignerInfo, error) {
	logger := log.GetLogger(ctx)
	logger.Debugf("Generic signing for %v in signature media type %v", desc.Digest, opts.SignatureMediaType)
	// Generate payload to be signed.
	payload := envelope.Payload{TargetArtifact: envelope.SanitizeTargetArtifact(desc)}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("envelope payload can't be marshalled: %w", err)
	}

	var signingAgentId string
	if opts.SigningAgent != "" {
		signingAgentId = opts.SigningAgent
	} else {
		signingAgentId = signingAgent
	}
	signReq := &signature.SignRequest{
		Payload: signature.Payload{
			ContentType: envelope.MediaTypePayloadV1,
			Content:     payloadBytes,
		},
		Signer:        s.Signer,
		SigningTime:   time.Now(),
		SigningScheme: signature.SigningSchemeX509,
		SigningAgent:  signingAgentId,
	}

	// Add expiry only if ExpiryDuration is not zero
	if opts.ExpiryDuration != 0 {
		signReq.Expiry = signReq.SigningTime.Add(opts.ExpiryDuration)
	}
	logger.Debugf("Sign request:")
	logger.Debugf("  ContentType:   %v", signReq.Payload.ContentType)
	logger.Debugf("  Content:       %s", string(signReq.Payload.Content))
	logger.Debugf("  SigningTime:   %v", signReq.SigningTime)
	logger.Debugf("  Expiry:        %v", signReq.Expiry)
	logger.Debugf("  SigningScheme: %v", signReq.SigningScheme)
	logger.Debugf("  SigningAgent:  %v", signReq.SigningAgent)

	// perform signing
	sigEnv, err := signature.NewEnvelope(opts.SignatureMediaType)
	if err != nil {
		return nil, nil, err
	}

	sig, err := sigEnv.Sign(signReq)
	if err != nil {
		return nil, nil, err
	}

	envContent, err := sigEnv.Verify()
	if err != nil {
		return nil, nil, fmt.Errorf("generated signature failed verification: %v", err)
	}
	if err := envelope.ValidatePayloadContentType(&envContent.Payload); err != nil {
		return nil, nil, err
	}

	// TODO: re-enable timestamping https://github.com/notaryproject/notation-go/issues/78
	return sig, &envContent.SignerInfo, nil
}
