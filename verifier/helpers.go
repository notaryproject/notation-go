package verifier

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
)

func loadX509TrustStores(ctx context.Context, scheme signature.SigningScheme, policy *trustpolicy.TrustPolicy) ([]*x509.Certificate, error) {
	var typeToLoad truststore.Type
	switch scheme {
	case signature.SigningSchemeX509:
		typeToLoad = truststore.TypeCA
	case signature.SigningSchemeX509SigningAuthority:
		typeToLoad = truststore.TypeSigningAuthority
	default:
		return nil, fmt.Errorf("unrecognized signing scheme %q", scheme)
	}

	var processedStoreSet = make(map[string]struct{})
	var certificates []*x509.Certificate
	x509TrustStore := truststore.NewX509TrustStore(dir.ConfigFS())
	for _, trustStore := range policy.TrustStores {
		if _, ok := processedStoreSet[trustStore]; ok {
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
		processedStoreSet[trustStore] = struct{}{}
	}
	return certificates, nil
}
