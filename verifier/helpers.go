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
	"errors"
	"fmt"
	"strings"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go"
	set "github.com/notaryproject/notation-go/internal/container"
	notationsemver "github.com/notaryproject/notation-go/internal/semver"
	"github.com/notaryproject/notation-go/internal/slices"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
)

const (
	// HeaderVerificationPlugin specifies the name of the verification plugin
	// that should be used to verify the signature.
	HeaderVerificationPlugin = "io.cncf.notary.verificationPlugin"

	// HeaderVerificationPluginMinVersion specifies the minimum version of the
	// verification plugin that should be used to verify the signature.
	HeaderVerificationPluginMinVersion = "io.cncf.notary.verificationPluginMinVersion"
)

// VerificationPluginHeaders specifies headers of a verification plugin
var VerificationPluginHeaders = []string{
	HeaderVerificationPlugin,
	HeaderVerificationPluginMinVersion,
}

var errExtendedAttributeNotExist = errors.New("extended attribute not exist")

func loadX509TrustStores(ctx context.Context, scheme signature.SigningScheme, policyName string, trustStores []string, x509TrustStore truststore.X509TrustStore) ([]*x509.Certificate, error) {
	var typeToLoad truststore.Type
	switch scheme {
	case signature.SigningSchemeX509:
		typeToLoad = truststore.TypeCA
	case signature.SigningSchemeX509SigningAuthority:
		typeToLoad = truststore.TypeSigningAuthority
	default:
		return nil, truststore.TrustStoreError{Msg: fmt.Sprintf("error while loading the trust store, unrecognized signing scheme %q", scheme)}
	}

	processedStoreSet := set.New[string]()
	var certificates []*x509.Certificate
	for _, trustStore := range trustStores {
		if processedStoreSet.Contains(trustStore) {
			// we loaded this trust store already
			continue
		}

		storeType, name, found := strings.Cut(trustStore, ":")
		if !found {
			return nil, truststore.TrustStoreError{Msg: fmt.Sprintf("error while loading the trust store, trust policy statement %q is missing separator in trust store value %q. The required format is <TrustStoreType>:<TrustStoreName>", policyName, trustStore)}
		}
		if typeToLoad != truststore.Type(storeType) {
			continue
		}

		certs, err := x509TrustStore.GetCertificates(ctx, typeToLoad, name)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certs...)
		processedStoreSet.Add(trustStore)
	}
	return certificates, nil
}

// isCriticalFailure checks whether a VerificationResult fails the entire
// signature verification workflow.
// signature verification workflow is considered failed if there is a
// VerificationResult with "Enforced" as the action but the result was
// unsuccessful.
func isCriticalFailure(result *notation.ValidationResult) bool {
	return result.Action == trustpolicy.ActionEnforce && result.Error != nil
}

func getNonPluginExtendedCriticalAttributes(signerInfo *signature.SignerInfo) []signature.Attribute {
	var criticalExtendedAttrs []signature.Attribute
	for _, attr := range signerInfo.SignedAttributes.ExtendedAttributes {
		attrStrKey, ok := attr.Key.(string)
		// filter the plugin extended attributes
		if ok && !slices.Contains(VerificationPluginHeaders, attrStrKey) {
			// TODO support other attribute types
			// (COSE attribute keys can be numbers)
			criticalExtendedAttrs = append(criticalExtendedAttrs, attr)
		}
	}
	return criticalExtendedAttrs
}

// extractCriticalStringExtendedAttribute extracts a critical string Extended
// attribute from a signer.
func extractCriticalStringExtendedAttribute(signerInfo *signature.SignerInfo, key string) (string, error) {
	attr, err := signerInfo.ExtendedAttribute(key)
	// not exist
	if err != nil {
		return "", errExtendedAttributeNotExist
	}
	// not critical
	if !attr.Critical {
		return "", fmt.Errorf("%v is not a critical Extended attribute", key)
	}
	// not string
	val, ok := attr.Value.(string)
	if !ok {
		return "", fmt.Errorf("%v from extended attribute is not a string", key)
	}
	return val, nil
}

// getVerificationPlugin get plugin name from the Extended attributes.
func getVerificationPlugin(signerInfo *signature.SignerInfo) (string, error) {
	name, err := extractCriticalStringExtendedAttribute(signerInfo, HeaderVerificationPlugin)
	if err != nil {
		return "", err
	}
	// not an empty string
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("%v from extended attribute is an empty string", HeaderVerificationPlugin)
	}
	return name, nil
}

// getVerificationPlugin get plugin version from the Extended attributes.
func getVerificationPluginMinVersion(signerInfo *signature.SignerInfo) (string, error) {
	version, err := extractCriticalStringExtendedAttribute(signerInfo, HeaderVerificationPluginMinVersion)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(version) == "" {
		return "", fmt.Errorf("%v from extended attribute is an empty string", HeaderVerificationPluginMinVersion)
	}
	if !notationsemver.IsValid(version) {
		return "", fmt.Errorf("%v from extended attribute is not a valid SemVer", HeaderVerificationPluginMinVersion)
	}
	return version, nil
}
