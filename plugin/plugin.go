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

// Package plugin provides the tooling to use the notation plugin.
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
	"strings"

	"github.com/notaryproject/notation-go/internal/io"
	"github.com/notaryproject/notation-go/internal/slices"
	"github.com/notaryproject/notation-go/log"
	"github.com/notaryproject/notation-go/plugin/proto"
	"github.com/notaryproject/notation-plugin-framework-go/plugin"
)

// maxPluginOutputSize is the maximum size of the plugin output.
const maxPluginOutputSize = 64 * 1024 * 1024 // 64 MiB

var executor commander = &execCommander{} // for unit test

// GenericPlugin is the base requirement to be a plugin.
//
// Deprecated: GenericPlugin exists for historical compatibility and should not be used.
// To access GenericPlugin, use the notation-plugin-framework-go's plugin.GenericPlugin type.
type GenericPlugin = plugin.GenericPlugin

// SignPlugin defines the required methods to be a SignPlugin.
//
// Deprecated: SignPlugin exists for historical compatibility and should not be used.
// To access SignPlugin, use the notation-plugin-framework-go's plugin.SignPlugin type.
type SignPlugin = plugin.SignPlugin

// VerifyPlugin defines the required method to be a VerifyPlugin.
//
// Deprecated: VerifyPlugin exists for historical compatibility and should not be used.
// To access VerifyPlugin, use the notation-plugin-framework-go's plugin.VerifyPlugin type.
type VerifyPlugin = plugin.VerifyPlugin

// Plugin defines required methods to be a Plugin.
//
// Deprecated: Plugin exists for historical compatibility and should not be used.
// To access Plugin, use the notation-plugin-framework-go's plugin.Plugin type.
type Plugin = plugin.Plugin

// CLIPlugin implements Plugin interface to CLI plugins.
type CLIPlugin struct {
	name string
	path string
}

// NewCLIPlugin returns a *CLIPlugin.
func NewCLIPlugin(ctx context.Context, name, path string) (*CLIPlugin, error) {
	// validate file existence
	fi, err := os.Stat(path)
	if err != nil {
		// Ignore any file which we cannot Stat
		// (e.g. due to permissions or anything else).
		return nil, fmt.Errorf("plugin executable file is either not found or inaccessible: %w", err)
	}
	if !fi.Mode().IsRegular() {
		// Ignore non-regular files.
		return nil, ErrNotRegularFile
	}

	// generate plugin
	return &CLIPlugin{
		name: name,
		path: path,
	}, nil
}

// GetMetadata returns the metadata information of the plugin.
func (p *CLIPlugin) GetMetadata(ctx context.Context, req *plugin.GetMetadataRequest) (*plugin.GetMetadataResponse, error) {
	var metadata plugin.GetMetadataResponse
	err := run(ctx, p.name, p.path, req, &metadata)
	if err != nil {
		return nil, err
	}
	// validate metadata
	if err = validate(&metadata); err != nil {
		return nil, &PluginMalformedError{
			Msg:        fmt.Sprintf("metadata validation failed for plugin %s: %s", p.name, err),
			InnerError: err,
		}
	}
	if metadata.Name != p.name {
		return nil, fmt.Errorf("plugin executable file name must be %q instead of %q", binName(metadata.Name), filepath.Base(p.path))
	}
	return &metadata, nil
}

// DescribeKey returns the KeySpec of a key.
//
// if ContractVersion is not set, it will be set by the function.
func (p *CLIPlugin) DescribeKey(ctx context.Context, req *plugin.DescribeKeyRequest) (*plugin.DescribeKeyResponse, error) {
	if req.ContractVersion == "" {
		req.ContractVersion = plugin.ContractVersion
	}

	var resp plugin.DescribeKeyResponse
	err := run(ctx, p.name, p.path, req, &resp)
	return &resp, err
}

// GenerateSignature generates the raw signature based on the request.
//
// if ContractVersion is not set, it will be set by the function.
func (p *CLIPlugin) GenerateSignature(ctx context.Context, req *plugin.GenerateSignatureRequest) (*plugin.GenerateSignatureResponse, error) {
	if req.ContractVersion == "" {
		req.ContractVersion = plugin.ContractVersion
	}

	var resp plugin.GenerateSignatureResponse
	err := run(ctx, p.name, p.path, req, &resp)
	return &resp, err
}

// GenerateEnvelope generates the Envelope with signature based on the request.
//
// if ContractVersion is not set, it will be set by the function.
func (p *CLIPlugin) GenerateEnvelope(ctx context.Context, req *plugin.GenerateEnvelopeRequest) (*plugin.GenerateEnvelopeResponse, error) {
	if req.ContractVersion == "" {
		req.ContractVersion = plugin.ContractVersion
	}

	var resp plugin.GenerateEnvelopeResponse
	err := run(ctx, p.name, p.path, req, &resp)
	return &resp, err
}

// VerifySignature validates the signature based on the request.
//
// if ContractVersion is not set, it will be set by the function.
func (p *CLIPlugin) VerifySignature(ctx context.Context, req *plugin.VerifySignatureRequest) (*plugin.VerifySignatureResponse, error) {
	if req.ContractVersion == "" {
		req.ContractVersion = plugin.ContractVersion
	}

	var resp plugin.VerifySignatureResponse
	err := run(ctx, p.name, p.path, req, &resp)
	return &resp, err
}

func run(ctx context.Context, pluginName string, pluginPath string, req plugin.Request, resp interface{}) error {
	logger := log.GetLogger(ctx)

	// serialize request
	data, err := json.Marshal(req)
	if err != nil {
		logger.Errorf("Failed to marshal request object: %+v", req)
		return fmt.Errorf("failed to marshal request object: %w", err)
	}

	logger.Debugf("Plugin %s request: %s", req.Command(), string(data))
	// execute request
	stdout, stderr, err := executor.Output(ctx, pluginPath, req.Command(), data)
	if err != nil {
		logger.Errorf("plugin %s execution status: %v", req.Command(), err)

		if len(stderr) == 0 {
			// if stderr is empty, it is possible that the plugin is not
			// running properly.
			logger.Errorf("failed to execute the %s command for plugin %s: %s", req.Command(), pluginName, err)
			return &PluginExecutableFileError{
				InnerError: err,
			}
		} else {
			var re proto.RequestError
			jsonErr := json.Unmarshal(stderr, &re)
			if jsonErr != nil {
				logger.Errorf("failed to execute the %s command for plugin %s: %s", req.Command(), pluginName, strings.TrimSuffix(string(stderr), "\n"))
				return &PluginMalformedError{
					InnerError: jsonErr,
				}
			}
			logger.Errorf("failed to execute the %s command for plugin %s: %s: %w", req.Command(), pluginName, re.Code, re)
			return re
		}
	}

	logger.Debugf("Plugin %s response: %s", req.Command(), string(stdout))
	// deserialize response
	if err = json.Unmarshal(stdout, resp); err != nil {
		logger.Errorf("failed to unmarshal plugin %s response: %w", req.Command(), err)
		return &PluginMalformedError{
			Msg:        fmt.Sprintf("failed to unmarshal the response of %s command for plugin %s", req.Command(), pluginName),
			InnerError: err,
		}
	}
	return nil
}

// commander is defined for mocking purposes.
type commander interface {
	// Output runs the command, passing req to the stdin.
	// It only returns an error if the binary can't be executed.
	// Returns stdout if err is nil, stderr if err is not nil.
	Output(ctx context.Context, path string, command plugin.Command, req []byte) (stdout []byte, stderr []byte, err error)
}

// execCommander implements the commander interface using exec.Command().
type execCommander struct{}

func (c execCommander) Output(ctx context.Context, name string, command plugin.Command, req []byte) ([]byte, []byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, string(command))
	cmd.Stdin = bytes.NewReader(req)
	// The limit writer will be handled by the caller in run() by comparing the
	// bytes written with the expected length of the bytes.
	cmd.Stderr = io.LimitWriter(&stderr, maxPluginOutputSize)
	cmd.Stdout = io.LimitWriter(&stdout, maxPluginOutputSize)
	err := cmd.Run()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, stderr.Bytes(), fmt.Errorf("'%s %s' command execution timeout: %w", name, string(command), err)
		}
		return nil, stderr.Bytes(), err
	}
	return stdout.Bytes(), nil, nil
}

// validate checks if the metadata is correctly populated.
func validate(metadata *plugin.GetMetadataResponse) error {
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
	if !slices.Contains(metadata.SupportedContractVersions, plugin.ContractVersion) {
		return fmt.Errorf(
			"contract version %q is not in the list of the plugin supported versions %v",
			plugin.ContractVersion, metadata.SupportedContractVersions,
		)
	}
	return nil
}
