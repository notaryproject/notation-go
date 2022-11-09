package verifier

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
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