package verifier

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/internal/common"
	"github.com/notaryproject/notation-go/verification/trustpolicy"
	"github.com/notaryproject/notation-go/verification/truststore"
)

func loadPolicyDocument() (*trustpolicy.Document, error) {
	policyDocument := &trustpolicy.Document{}
	jsonFile, err := dir.ConfigFS().Open(dir.PathTrustPolicy)
	if err != nil {
		return nil, err
	}
	defer jsonFile.Close()
	err = json.NewDecoder(jsonFile).Decode(policyDocument)
	if err != nil {
		return nil, err
	}
	return policyDocument, nil
}

func loadX509TrustStores(ctx context.Context, scheme signature.SigningScheme, policy *trustpolicy.TrustPolicy) ([]*x509.Certificate, error) {
	var typeToLoad truststore.Type
	if scheme == signature.SigningSchemeX509 {
		typeToLoad = truststore.TypeCA
	} else if scheme == signature.SigningSchemeX509SigningAuthority {
		typeToLoad = truststore.TypeSigningAuthority
	} else {
		return nil, fmt.Errorf("unrecognized signing scheme %q", scheme)
	}

	var namedStoreSet = make(map[string]struct{})
	var certificates []*x509.Certificate
	x509TrustStore := truststore.NewX509TrustStore(dir.ConfigFS())
	for _, trustStore := range policy.TrustStores {
		if _, ok := namedStoreSet[trustStore]; ok {
			// we loaded this trust store already
			continue
		}

		i := strings.Index(trustStore, ":")
		storeType := trustStore[:i]
		if typeToLoad != truststore.Type(storeType) {
			continue
		}
		name := trustStore[i+1:]
		certs, err := x509TrustStore.GetCertificates(ctx, typeToLoad, name)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certs...)
		namedStoreSet[trustStore] = struct{}{}
	}
	return certificates, nil
}

func isPresentAny(val interface{}, values []interface{}) bool {
	for _, v := range values {
		if v == val {
			return true
		}
	}
	return false
}

func getArtifactPathFromReference(artifactReference string) (string, error) {
	// TODO support more types of URI like "domain.com/repository", "domain.com/repository:tag"
	i := strings.LastIndex(artifactReference, "@")
	if i < 0 {
		return "", fmt.Errorf("artifact URI %q could not be parsed, make sure it is the fully qualified OCI artifact URI without the scheme/protocol. e.g domain.com:80/my/repository@sha256:digest", artifactReference)
	}

	artifactPath := artifactReference[:i]
	if err := common.ValidateRegistryScopeFormat(artifactPath); err != nil {
		return "", err
	}
	return artifactPath, nil
}

func getArtifactDigestFromReference(artifactReference string) (string, error) {
	invalidUriErr := fmt.Errorf("artifact URI %q could not be parsed, make sure it is the fully qualified OCI artifact URI without the scheme/protocol. e.g domain.com:80/my/repository@sha256:digest", artifactReference)
	i := strings.LastIndex(artifactReference, "@")
	if i < 0 || i+1 == len(artifactReference) {
		return "", invalidUriErr
	}

	j := strings.LastIndex(artifactReference[i+1:], ":")
	if j < 0 || j+1 == len(artifactReference[i+1:]) {
		return "", invalidUriErr
	}

	return artifactReference[i+1:], nil
}

// getApplicableTrustPolicy returns a pointer to the deep copied TrustPolicy statement that applies to the given
// registry URI. If no applicable trust policy is found, returns an error
// see https://github.com/notaryproject/notaryproject/blob/main/trust-store-trust-policy-specification.md#selecting-a-trust-policy-based-on-artifact-uri
func getApplicableTrustPolicy(policyDoc *trustpolicy.Document, artifactReference string) (*trustpolicy.TrustPolicy, error) {

	artifactPath, err := getArtifactPathFromReference(artifactReference)
	if err != nil {
		return nil, err
	}

	var wildcardPolicy *trustpolicy.TrustPolicy
	var applicablePolicy *trustpolicy.TrustPolicy
	for _, policyStatement := range policyDoc.TrustPolicies {
		if common.IsPresent(common.Wildcard, policyStatement.RegistryScopes) {
			wildcardPolicy = deepCopy(&policyStatement) // we need to deep copy because we can't use the loop variable address. see https://stackoverflow.com/a/45967429
		} else if common.IsPresent(artifactPath, policyStatement.RegistryScopes) {
			applicablePolicy = deepCopy(&policyStatement)
		}
	}

	if applicablePolicy != nil {
		// a policy with exact match for registry URI takes precedence over a wildcard (*) policy.
		return applicablePolicy, nil
	} else if wildcardPolicy != nil {
		return wildcardPolicy, nil
	} else {
		return nil, fmt.Errorf("artifact %q has no applicable trust policy", artifactReference)
	}
}

// deepCopy returns a pointer to the deeply copied TrustPolicy
func deepCopy(t *trustpolicy.TrustPolicy) *trustpolicy.TrustPolicy {
	return &trustpolicy.TrustPolicy{
		Name:                  t.Name,
		SignatureVerification: t.SignatureVerification,
		RegistryScopes:        append([]string(nil), t.RegistryScopes...),
		TrustedIdentities:     append([]string(nil), t.TrustedIdentities...),
		TrustStores:           append([]string(nil), t.TrustStores...),
	}
}
