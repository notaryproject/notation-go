// Package plugin provides the toolings to use the notation plugin.
//
// includes a CLIManager and a CLIPlugin implementation.
package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"

	"github.com/notaryproject/notation-go/plugin/proto"
)

var executor commander = &execCommander{} // for unit test

// GenericPlugin is the base requirement to be an plugin.
type GenericPlugin interface {
	GetMetadata(ctx context.Context, req *proto.GetMetadataRequest) (*proto.GetMetadataResponse, error)
}

// SignPlugin defines the required methods to be a SignPlugin.
type SignPlugin interface {
	GenericPlugin

	// DescribeKey returns the KeySpec of a key.
	DescribeKey(ctx context.Context, req *proto.DescribeKeyRequest) (*proto.DescribeKeyResponse, error)

	// GenerateSignature generates the raw signature based on the request.
	GenerateSignature(ctx context.Context, req *proto.GenerateSignatureRequest) (*proto.GenerateSignatureResponse, error)

	// GenerateEnvelope generates the Envelope with signature based on the request.
	GenerateEnvelope(ctx context.Context, req *proto.GenerateEnvelopeRequest) (*proto.GenerateEnvelopeResponse, error)
}

// VerifyPlugin defines the required method to be a VerifyPlugin.
type VerifyPlugin interface {
	GenericPlugin

	// VerifySignature validates the signature based on the request.
	VerifySignature(ctx context.Context, req *proto.VerifySignatureRequest) (*proto.VerifySignatureResponse, error)
}

// Plugin defines required methods to be an Plugin.
type Plugin interface {
	SignPlugin
	VerifyPlugin
}

// CLIPlugin implements Plugin interface to CLI plugins.
type CLIPlugin struct {
	name string
	path string
}

func (p *CLIPlugin) GetMetadata(ctx context.Context, req *proto.GetMetadataRequest) (*proto.GetMetadataResponse, error) {
	var resp proto.GetMetadataResponse
	err := run(ctx, p.name, p.path, req, &resp)
	return &resp, err
}

func (p *CLIPlugin) DescribeKey(ctx context.Context, req *proto.DescribeKeyRequest) (*proto.DescribeKeyResponse, error) {
	var resp proto.DescribeKeyResponse
	err := run(ctx, p.name, p.path, req, &resp)
	return &resp, err
}

func (p *CLIPlugin) GenerateSignature(ctx context.Context, req *proto.GenerateSignatureRequest) (*proto.GenerateSignatureResponse, error) {
	var resp proto.GenerateSignatureResponse
	err := run(ctx, p.name, p.path, req, &resp)
	return &resp, err
}

func (p *CLIPlugin) GenerateEnvelope(ctx context.Context, req *proto.GenerateEnvelopeRequest) (*proto.GenerateEnvelopeResponse, error) {
	var resp proto.GenerateEnvelopeResponse
	err := run(ctx, p.name, p.path, req, &resp)
	return &resp, err
}

func (p *CLIPlugin) VerifySignature(ctx context.Context, req *proto.VerifySignatureRequest) (*proto.VerifySignatureResponse, error) {
	var resp proto.VerifySignatureResponse
	err := run(ctx, p.name, p.path, req, &resp)
	return &resp, err
}

// NewCLIPlugin validate the metadata of the plugin and return a *CLIPlugin.
func NewCLIPlugin(ctx context.Context, name, path string) (*CLIPlugin, error) {
	plugin := CLIPlugin{
		name: name,
		path: path,
	}

	// validate metadata
	metadata, err := plugin.GetMetadata(ctx, &proto.GetMetadataRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metadata: %w", err)
	}
	if metadata.Name != name {
		return nil, fmt.Errorf("executable name must be %q instead of %q", binName(metadata.Name), filepath.Base(path))
	}
	if err = metadata.Validate(); err != nil {
		return nil, fmt.Errorf("invalid metadata: %w", err)
	}

	return &plugin, nil
}

func run(ctx context.Context, pluginName string, pluginPath string, req proto.Request, resp interface{}) error {
	// serialize request
	data, err := json.Marshal(req)
	if err != nil {

		return fmt.Errorf("%s: failed to marshal request object: %w", pluginName, err)
	}

	// execute request
	out, err := executor.Output(ctx, pluginPath, req.Command(), data)
	if err != nil {
		var re proto.RequestError
		err = json.Unmarshal(out, &re)
		if err != nil {
			return proto.RequestError{Code: proto.ErrorCodeGeneric, Err: err}
		}
		return re
	}

	// deserialize response
	err = json.Unmarshal(out, resp)
	if err != nil {
		return fmt.Errorf("failed to decode json response: %w", ErrNotCompliant)
	}
	return nil
}

// commander is defined for mocking purposes.
type commander interface {
	// Output runs the command, passing req to the its stdin.
	// It only returns an error if the binary can't be executed.
	// Returns stdout if err is nil, stderr if err is not nil.
	Output(ctx context.Context, path string, command proto.Command, req []byte) (out []byte, err error)
}

// execCommander implements the commander interface using exec.Command().
type execCommander struct{}

func (c execCommander) Output(ctx context.Context, name string, command proto.Command, req []byte) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, string(command))
	cmd.Stdin = bytes.NewReader(req)
	return cmd.Output()
}
