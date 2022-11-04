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

const prefix = "notation-" // plugin prefix

var executableSuffix = "" // executable file suffix

var executor commander = &execCommander{} // for unit test

// PluginBase is the base requirement to be an plugin.
type PluginBase interface {
	GetMetadata(ctx context.Context, req *proto.GetMetadataRequest) (*proto.GetMetadataResponse, error)
}

// SignPlugin defines the required methods to be a SignPlugin.
type SignPlugin interface {
	PluginBase

	// DescribeKey returns the KeySpec of a key.
	DescribeKey(ctx context.Context, req *proto.DescribeKeyRequest) (*proto.DescribeKeyResponse, error)

	// GenerateSignature generates the raw signature based on the request.
	GenerateSignature(ctx context.Context, req *proto.GenerateSignatureRequest) (*proto.GenerateSignatureResponse, error)

	// GenerateEnvelope generates the Envelope with signature based on the request.
	GenerateEnvelope(ctx context.Context, req *proto.GenerateEnvelopeRequest) (*proto.GenerateEnvelopeResponse, error)
}

// VerifyPlugin defines the required method to be a VerifyPlugin.
type VerifyPlugin interface {
	PluginBase

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
	err := run(ctx, p.name, p.path, executor, req, &resp)
	return &resp, err
}

func (p *CLIPlugin) DescribeKey(ctx context.Context, req *proto.DescribeKeyRequest) (*proto.DescribeKeyResponse, error) {
	var resp proto.DescribeKeyResponse
	err := run(ctx, p.name, p.path, executor, req, &resp)
	return &resp, err
}

func (p *CLIPlugin) GenerateSignature(ctx context.Context, req *proto.GenerateSignatureRequest) (*proto.GenerateSignatureResponse, error) {
	var resp proto.GenerateSignatureResponse
	err := run(ctx, p.name, p.path, executor, req, &resp)
	return &resp, err
}

func (p *CLIPlugin) GenerateEnvelope(ctx context.Context, req *proto.GenerateEnvelopeRequest) (*proto.GenerateEnvelopeResponse, error) {
	var resp proto.GenerateEnvelopeResponse
	err := run(ctx, p.name, p.path, executor, req, &resp)
	return &resp, err
}

func (p *CLIPlugin) VerifySignature(ctx context.Context, req *proto.VerifySignatureRequest) (*proto.VerifySignatureResponse, error) {
	var resp proto.VerifySignatureResponse
	err := run(ctx, p.name, p.path, executor, req, &resp)
	return &resp, err
}

// NewCLIPlugin validate the metadata of the plugin and return a *CLIPlugin.
func NewCLIPlugin(name, path string) (*CLIPlugin, error) {
	plugin := CLIPlugin{
		name: name,
		path: path,
	}

	// validate metadata
	metadata, err := plugin.GetMetadata(context.Background(), &proto.GetMetadataRequest{})
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

func run(ctx context.Context, pluginName string, pluginPath string, cmder commander, req proto.Request, resp interface{}) error {
	// serialize request
	data, err := json.Marshal(req)
	if err != nil {
		return pluginErr(pluginName, fmt.Errorf("failed to marshal request object: %w", err))
	}

	// execute request
	out, err := cmder.Output(ctx, pluginPath, string(req.Command()), data)
	if err != nil {
		var re proto.RequestError
		err = json.Unmarshal(out, &re)
		if err != nil {
			return proto.RequestError{Code: proto.ErrorCodeGeneric, Err: fmt.Errorf("error: %v. stderr: %s", err, out)}
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
	Output(ctx context.Context, path string, command string, req []byte) (out []byte, err error)
}

// execCommander implements the commander interface using exec.Command().
type execCommander struct{}

func (c execCommander) Output(ctx context.Context, name string, command string, req []byte) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, command)
	cmd.Stdin = bytes.NewReader(req)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return stderr.Bytes(), err
	}
	return stdout.Bytes(), nil
}

func pluginErr(name string, err error) error {
	return fmt.Errorf("%s: %w", name, err)
}
