// Package plugin provides the toolings to use the notation plugin.
//
// includes a CLIManager and a CLIPlugin implementation.
package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/notaryproject/notation-go/internal/slices"
	"github.com/notaryproject/notation-go/plugin/proto"
)

var executor commander = &execCommander{} // for unit test

// GenericPlugin is the base requirement to be an plugin.
type GenericPlugin interface {
	// GetMetadata returns the metadata information of the plugin.
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

// NewCLIPlugin validate the metadata of the plugin and return a *CLIPlugin.
func NewCLIPlugin(ctx context.Context, name, path string) (*CLIPlugin, error) {
	// validate file existence
	fi, err := os.Stat(path)
	if err != nil {
		// Ignore any file which we cannot Stat
		// (e.g. due to permissions or anything else).
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		// Ignore non-regular files.
		return nil, ErrNotRegularFile
	}

	// generate plugin
	plugin := CLIPlugin{
		name: name,
		path: path,
	}
	return &plugin, nil
}

// GetMetadata returns the metadata information of the plugin.
func (p *CLIPlugin) GetMetadata(ctx context.Context, req *proto.GetMetadataRequest) (*proto.GetMetadataResponse, error) {
	var metadata proto.GetMetadataResponse
	err := run(ctx, p.name, p.path, req, &metadata)
	if err != nil {
		return nil, err
	}
	// validate metadata
	if err = validate(&metadata); err != nil {
		return nil, fmt.Errorf("invalid metadata: %w", err)
	}
	if metadata.Name != p.name {
		return nil, fmt.Errorf("executable name must be %q instead of %q", binName(metadata.Name), filepath.Base(p.path))
	}
	return &metadata, nil
}

// DescribeKey returns the KeySpec of a key.
//
// if ContractVersion is not set, it will be set by the function.
func (p *CLIPlugin) DescribeKey(ctx context.Context, req *proto.DescribeKeyRequest) (*proto.DescribeKeyResponse, error) {
	var resp proto.DescribeKeyResponse
	if req.ContractVersion == "" {
		req.ContractVersion = proto.ContractVersion
	}
	err := run(ctx, p.name, p.path, req, &resp)
	return &resp, err
}

// GenerateSignature generates the raw signature based on the request.
//
// if ContractVersion is not set, it will be set by the function.
func (p *CLIPlugin) GenerateSignature(ctx context.Context, req *proto.GenerateSignatureRequest) (*proto.GenerateSignatureResponse, error) {
	var resp proto.GenerateSignatureResponse
	if req.ContractVersion == "" {
		req.ContractVersion = proto.ContractVersion
	}
	err := run(ctx, p.name, p.path, req, &resp)
	return &resp, err
}

// GenerateEnvelope generates the Envelope with signature based on the request.
//
// if ContractVersion is not set, it will be set by the function.
func (p *CLIPlugin) GenerateEnvelope(ctx context.Context, req *proto.GenerateEnvelopeRequest) (*proto.GenerateEnvelopeResponse, error) {
	var resp proto.GenerateEnvelopeResponse
	if req.ContractVersion == "" {
		req.ContractVersion = proto.ContractVersion
	}
	err := run(ctx, p.name, p.path, req, &resp)
	return &resp, err
}

// VerifySignature validates the signature based on the request.
//
// if ContractVersion is not set, it will be set by the function.
func (p *CLIPlugin) VerifySignature(ctx context.Context, req *proto.VerifySignatureRequest) (*proto.VerifySignatureResponse, error) {
	var resp proto.VerifySignatureResponse
	if req.ContractVersion == "" {
		req.ContractVersion = proto.ContractVersion
	}
	err := run(ctx, p.name, p.path, req, &resp)
	return &resp, err
}

func run(ctx context.Context, pluginName string, pluginPath string, req proto.Request, resp interface{}) error {
	// serialize request
	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("%s: failed to marshal request object: %w", pluginName, err)
	}

	// execute request
	stdout, stderr, err := executor.Output(ctx, pluginPath, req.Command(), data)
	if err != nil {
		var re proto.RequestError
		jsonErr := json.Unmarshal(stderr, &re)
		if jsonErr != nil {
			return proto.RequestError{
				Code: proto.ErrorCodeGeneric,
				Err:  fmt.Errorf("response is not in JSON format. error: %v stderr: %v", err, stderr)}
		}
		return re
	}

	// deserialize response
	err = json.Unmarshal(stdout, resp)
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
	Output(ctx context.Context, path string, command proto.Command, req []byte) (stdout []byte, stderr []byte, err error)
}

// execCommander implements the commander interface using exec.Command().
type execCommander struct{}

func (c execCommander) Output(ctx context.Context, name string, command proto.Command, req []byte) ([]byte, []byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, string(command))
	cmd.Stdin = bytes.NewReader(req)
	cmd.Stderr = &stderr
	cmd.Stdout = &stdout
	err := cmd.Run()
	if err != nil {
		return nil, stderr.Bytes(), err
	}
	return stdout.Bytes(), nil, nil
}

// validate checks if the metadata is correctly populated.
func validate(metadata *proto.GetMetadataResponse) error {
	if metadata.Name == "" {
		return errors.New("empty name")
	}
	if metadata.Description == "" {
		return errors.New("empty description")
	}
	if metadata.Version == "" {
		return errors.New("empty version")
	}
	if metadata.URL == "" {
		return errors.New("empty url")
	}
	if len(metadata.Capabilities) == 0 {
		return errors.New("empty capabilities")
	}
	if len(metadata.SupportedContractVersions) == 0 {
		return errors.New("supported contract versions not specified")
	}
	if !slices.Contains(metadata.SupportedContractVersions, proto.ContractVersion) {
		return fmt.Errorf(
			"contract version %q is not in the list of the plugin supported versions %v",
			proto.ContractVersion, metadata.SupportedContractVersions,
		)
	}
	return nil
}
