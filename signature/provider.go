package signature

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go/plugin"
)

// provider wraps a runner and a signature.Signer
type provider interface {
	plugin.Runner
	signature.Signer
	SetConfig(map[string]string)
}

// builtinPlugin is a builtin provider implementation
// It only support describe key and metadata command
// It wraps signature.Signature to support builtin signing method
type builtinProvider struct {
	signature.LocalSigner
}

func newBuiltinProvider(key crypto.PrivateKey, certChain []*x509.Certificate) (provider, error) {
	builtinSigner, err := signature.NewLocalSigner(certChain, key)
	if err != nil {
		return nil, err
	}
	return &builtinProvider{
		builtinSigner,
	}, nil
}

func (*builtinProvider) metadata() *plugin.Metadata {
	// The only properties that are really relevant
	// are the supported contract version and the capabilities.
	// All other are just filled with meaningful data.
	return &plugin.Metadata{
		SupportedContractVersions: []string{plugin.ContractVersion},
		Capabilities:              []plugin.Capability{plugin.CapabilitySignatureGenerator},
		Name:                      "built-in",
		Description:               "Notation built-in signer",
		Version:                   plugin.ContractVersion,
		URL:                       "https://github.com/notaryproject/notation-go",
	}
}

// SetConfig set config when signing
// no need to implement since builtin plugin never use config
func (*builtinProvider) SetConfig(map[string]string) {

}

// Run implement the plugin workflow.
// only support metadata and describe key
// TODO: how to return key spec
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

// builtinPlugin is a external provider implementation, which will interact with plugin
// It supports all plugin commands
// The detail implementation depends on the real plugin
// It wraps a signature.Signature to support external signing
type externalProvider struct {
	plugin.Runner
	keyID  string
	config map[string]string
}

// SetConfig setup config used by signing
func (p *externalProvider) SetConfig(cfg map[string]string) {
	p.config = cfg
}

func newExternalProvider(runner plugin.Runner, keyID string) provider {
	return &externalProvider{
		Runner: runner,
		keyID:  keyID,
	}
}

func (p *externalProvider) describeKey(ctx context.Context) (*plugin.DescribeKeyResponse, error) {
	req := &plugin.DescribeKeyRequest{
		ContractVersion: plugin.ContractVersion,
		KeyID:           p.keyID,
		PluginConfig:    p.config,
	}
	out, err := p.Run(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("describe-key command failed: %w", err)
	}
	resp, ok := out.(*plugin.DescribeKeyResponse)
	if !ok {
		return nil, fmt.Errorf("plugin runner returned incorrect describe-key response type '%T'", out)
	}
	return resp, nil
}

// Sign sign the digest by calling the real plugin
func (p *externalProvider) Sign(digest []byte) ([]byte, error) {
	// Execute plugin sign command.
	// TODO: do we still need keyspec and hash in request?
	keySpec, err := p.KeySpec()
	if err == nil {
		return nil, err
	}
	req := &plugin.GenerateSignatureRequest{
		ContractVersion: plugin.ContractVersion,
		KeyID:           p.keyID,
		KeySpec:         KeySpecName(keySpec),
		Hash:            KeySpecHashName(keySpec),
		Payload:         digest,
		PluginConfig:    p.config,
	}

	out, err := p.Run(context.Background(), req)
	if err != nil {
		return nil, fmt.Errorf("generate-signature command failed: %w", err)
	}

	resp, ok := out.(*plugin.GenerateSignatureResponse)
	if !ok {
		return nil, fmt.Errorf("plugin runner returned incorrect generate-signature response type '%T'", out)
	}

	// Check keyID is honored.
	if req.KeyID != resp.KeyID {
		return nil, fmt.Errorf("keyID in generateSignature response %q does not match request %q", resp.KeyID, req.KeyID)
	}

	// TODO: do we still need cert chain in response?
	if _, err = parseCertChain(resp.CertificateChain); err != nil {
		return nil, err
	}

	return resp.Signature, nil
}

func (p *externalProvider) keyInfo() (signature.KeySpec, []*x509.Certificate, error) {
	keyResp, err := p.describeKey(context.Background())
	if err != nil {
		return signature.KeySpec{}, nil, err
	}

	// Check keyID is honored.
	if p.keyID != keyResp.KeyID {
		return signature.KeySpec{}, nil, fmt.Errorf("keyID in describeKey response %q does not match request %q", keyResp.KeyID, p.keyID)
	}
	certs, err := parseCertChain(keyResp.CertificateChain)
	if err != nil {
		return signature.KeySpec{}, nil, err
	}
	return ParseKeySpecFromName(keyResp.KeySpec), certs, nil
}

func (p *externalProvider) CertificateChain() ([]*x509.Certificate, error) {
	_, certs, err := p.keyInfo()
	if err != nil {
		return nil, err
	}
	return certs, nil
}

func (p *externalProvider) KeySpec() (signature.KeySpec, error) {
	keySpec, _, err := p.keyInfo()
	if err != nil {
		return signature.KeySpec{}, err
	}
	return keySpec, nil
}
