package plugin

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
)

// We use the following variables to allow mocking them in tests.
var (
	stdout = os.Stdout
	stderr = os.Stderr
)

type validator interface {
	Validate() error
}

type RunFunc func(command Command, req interface{}) (interface{}, error)

func Run(metadata *Metadata, fn RunFunc) error {
	return RunWithFlagSet(nil, metadata, fn, os.Args[1:]...)
}

func RunWithFlagSet(flagset *flag.FlagSet, metadata *Metadata, fn RunFunc, args ...string) error {
	if len(args) < 1 {
		return ErrUnknownCommand
	}
	cmd := Command(args[0])
	switch cmd {
	default:
		// Not one of our commands.
		return ErrUnknownCommand
	case CommandGetMetadata:
		// Fast path.
		err := json.NewEncoder(stdout).Encode(metadata)
		if err != nil {
			return requestErr(err)
		}
		return nil
	case CommandGenerateSignature,
		CommandGenerateEnvelope:
		// Lets continue.
	}

	if c := cmd.Capability(); !metadata.HasCapability(c) {
		return requestErr(RequestError{Code: ErrorCodeValidation, Err: errors.New("missing capability: " + string(c))})
	}

	req, err := parseArgs(flagset, cmd, args)
	if err != nil {
		return requestErr(err)
	}

	resp, err := fn(cmd, req)
	if err != nil {
		return requestErr(err)
	}

	err = validateResponse(cmd, resp)
	if err != nil {
		return requestErr(err)
	}

	err = json.NewEncoder(stdout).Encode(resp)
	if err != nil {
		return requestErr(err)
	}
	return nil
}

func parseArgs(flagset *flag.FlagSet, cmd Command, args []string) (validator, error) {
	if flagset == nil {
		flagset = flag.NewFlagSet(string(cmd), flag.ExitOnError)
	} else {
		flagset.Init(string(cmd), flagset.ErrorHandling())
	}
	var req validator
	switch cmd {
	case CommandGenerateSignature:
		req = generateSignatureFlags(flagset)
	case CommandGenerateEnvelope:
		req = generateEnvelopFlags(flagset)
	default:
		panic("unsupported command: " + cmd)
	}
	flagset.Parse(args[1:])
	err := req.Validate()
	if err != nil {
		return nil, RequestError{Code: ErrorCodeValidation, Err: fmt.Errorf("input parameters: %w", err)}
	}
	return req, nil
}

func validateResponse(cmd Command, resp interface{}) error {
	if resp == nil {
		return errors.New("nil response")
	}
	var ok bool
	switch cmd {
	case CommandGenerateSignature:
		_, ok = resp.(*GenerateSignatureResponse)
	case CommandGenerateEnvelope:
		_, ok = resp.(*GenerateEnvelopeResponse)
	default:
		panic("unsupported command: " + cmd)
	}
	if !ok {
		return fmt.Errorf("invalid response type: %T", resp)
	}
	return nil
}

func requestErr(err error) error {
	if _, ok := err.(RequestError); !ok {
		err = RequestError{Code: ErrorCodeGeneric, Err: err}
	}
	json.NewEncoder(stderr).Encode(err)
	return err
}

func generateSignatureFlags(flagset *flag.FlagSet) *GenerateSignatureRequest {
	req := new(GenerateSignatureRequest)
	flagset.Func(ArgContractVersion[2:], "contract version in the form of <major-version.minor-version>", func(s string) error {
		req.ContractVersion = s
		return nil
	})
	flagset.Func(ArgKeyName[2:], "signing key name", func(s string) error {
		req.KeyName = s
		return nil
	})
	flagset.Func(ArgKeyID[2:], "signing key id", func(s string) error {
		req.KeyID = s
		return nil
	})
	return req
}

func generateEnvelopFlags(flagset *flag.FlagSet) *GenerateEnvelopeRequest {
	req := new(GenerateEnvelopeRequest)
	flagset.Func(ArgContractVersion[2:], "contract version in the form of <major-version.minor-version>", func(s string) error {
		req.ContractVersion = s
		return nil
	})
	flagset.Func(ArgKeyName[2:], "signing key name", func(s string) error {
		req.KeyName = s
		return nil
	})
	flagset.Func(ArgKeyID[2:], "signing key id", func(s string) error {
		req.KeyID = s
		return nil
	})
	flagset.Func(ArgPayloadType[2:], "payload type", func(s string) error {
		req.PayloadType = s
		return nil
	})
	flagset.Func(ArgSignatureEnvelopeType[2:], "expected response signature envelope", func(s string) error {
		req.SignatureEnvelopeType = s
		return nil
	})
	return req
}
