package signature

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go/plugin"
)

// builtInPluginMetaData is the metadata used by builtinProvider.
var builtInPluginMetaData = &plugin.Metadata{
	SupportedContractVersions: []string{plugin.ContractVersion},
	Capabilities:              []plugin.Capability{plugin.CapabilitySignatureGenerator},
	Name:                      "built-in",
	Description:               "Notation built-in signer",
	Version:                   plugin.ContractVersion,
	URL:                       "https://github.com/notaryproject/notation-go",
}

// provider wraps a plugin.Runner and a signature.Signer.
type provider interface {
	plugin.Runner
	signature.Signer
}

// builtinProvider is a builtin provider implementation
// which wraps the signature.Signature to support builtin signing method.
// It only supports describe key and metadata command.
type builtinProvider struct {
	signature.LocalSigner
}

// newBuiltinProvider creates a builtinProvider to support local signing.
func newBuiltinProvider(key crypto.PrivateKey, certChain []*x509.Certificate) (provider, error) {
	builtinSigner, err := signature.NewLocalSigner(certChain, key)
	if err != nil {
		return nil, err
	}
	return &builtinProvider{
		builtinSigner,
	}, nil
}

// metadata provides metadata for builtinProvider.
func (*builtinProvider) metadata() *plugin.Metadata {
	// The only properties that are really relevant
	// are the supported contract version and the capabilities.
	// All other are just filled with meaningful data.
	return builtInPluginMetaData
}

// Run implements the plugin workflow.
//
// builtinProvider only supports metadata and describe key.
func (p *builtinProvider) Run(_ context.Context, req plugin.Request) (interface{}, error) {
	switch req.Command() {
	case plugin.CommandGetMetadata:
		return p.metadata(), nil
	case plugin.CommandDescribeKey:
		req1 := req.(*plugin.DescribeKeyRequest)
		return &plugin.DescribeKeyResponse{
			KeyID: req1.KeyID,
		}, nil
	}
	return nil, plugin.RequestError{
		Code: plugin.ErrorCodeGeneric,
		Err:  fmt.Errorf("command %q is not supported", req.Command()),
	}
}

// externalProvider is an external provider implementation which will interact with plugin.
// It supports all plugin commands.
//
// The detail implementation depends on the underlying plugin.
//
// It wraps a signature.Signer to support external signing.
type externalProvider struct {
	plugin.Runner
	keyID   string
	config  map[string]string
	keySpec signature.KeySpec
}

// newExternalProvider creates an external provider.
func newExternalProvider(runner plugin.Runner, keyID string) provider {
	return &externalProvider{
		Runner: runner,
		keyID:  keyID,
	}
}

// prepareSigning sets up config and keySpec used to sign.
func (p *externalProvider) prepareSigning(cfg map[string]string, keySpec signature.KeySpec) {
	p.config = cfg
	p.keySpec = keySpec
}

// Sign signs the digest by calling the underlying plugin.
func (p *externalProvider) Sign(payload []byte) ([]byte, []*x509.Certificate, error) {
	// Execute plugin sign command.
	keySpec, err := p.KeySpec()
	if err != nil {
		return nil, nil, err
	}
	req := &plugin.GenerateSignatureRequest{
		ContractVersion: plugin.ContractVersion,
		KeyID:           p.keyID,
		KeySpec:         plugin.KeySpecString(keySpec),
		Hash:            plugin.KeySpecHashString(keySpec),
		Payload:         payload,
		PluginConfig:    p.config,
	}

	out, err := p.Run(context.Background(), req)
	if err != nil {
		return nil, nil, fmt.Errorf("generate-signature command failed: %w", err)
	}

	resp, ok := out.(*plugin.GenerateSignatureResponse)
	if !ok {
		return nil, nil, fmt.Errorf("plugin runner returned incorrect generate-signature response type '%T'", out)
	}

	// Check keyID is honored.
	if req.KeyID != resp.KeyID {
		return nil, nil, fmt.Errorf("keyID in generateSignature response %q does not match request %q", resp.KeyID, req.KeyID)
	}

	var certs []*x509.Certificate
	if certs, err = parseCertChain(resp.CertificateChain); err != nil {
		return nil, nil, err
	}
	return resp.Signature, certs, nil
}

// KeySpec returns the keySpec of a keyID by calling describeKey and do some keySpec validation.
func (p *externalProvider) KeySpec() (signature.KeySpec, error) {
	return p.keySpec, nil
}
