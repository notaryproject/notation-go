package signature

import (
	"context"
	"reflect"
	"testing"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go/plugin"
)

func TestProvider_Builtin_NewProvider(t *testing.T) {
	type builtinArgs struct {
		*keyCertPair
		expectedErr bool
	}
	var tests []builtinArgs
	for _, keyCert := range keyCertPairCollections {
		tests = append(tests, builtinArgs{
			keyCert,
			false,
		})
	}
	key1, cert1, _ := generateKeyCertPair()
	key2, cert2, _ := generateKeyCertPair()
	tests = append(tests,
		builtinArgs{
			keyCertPair: &keyCertPair{
				keySpecName: "no certs",
				key:         key1,
			},
			expectedErr: true,
		},
		builtinArgs{
			keyCertPair: &keyCertPair{
				keySpecName: "no key",
				certs:       cert2,
			},
			expectedErr: true,
		},
		builtinArgs{
			keyCertPair: &keyCertPair{
				keySpecName: "key cert mismatch",
				key:         key2,
				certs:       cert1,
			},
			expectedErr: true,
		},
	)
	for _, tt := range tests {
		t.Run(tt.keySpecName, func(t *testing.T) {
			if _, err := newBuiltinProvider(tt.key, tt.certs); (err != nil) != tt.expectedErr {
				t.Fatalf("new builtin provider failed, expectedErr: %v, got: %v", tt.expectedErr, err)
			}
		})
	}
}

type customerCommand struct{}

func (customerCommand) Command() plugin.Command {
	return "customer"
}

func TestProvider_Builtin_Runner(t *testing.T) {
	p, err := newBuiltinProvider(keyCertPairCollections[0].key, keyCertPairCollections[0].certs)
	if err != nil {
		t.Fatalf("expect newBuiltinProvider ok, got: %v", err)
	}

	tests := []struct {
		name         string
		req          plugin.Request
		ExpectedResp interface{}
		expectedErr  bool
	}{
		{
			name:         string(plugin.CommandGetMetadata),
			req:          &plugin.GetMetadataRequest{},
			ExpectedResp: builtInPluginMetaData,
			expectedErr:  false,
		},
		{
			name: string(plugin.CommandDescribeKey),
			req: &plugin.DescribeKeyRequest{
				KeyID: "key",
			},
			ExpectedResp: &plugin.DescribeKeyResponse{
				KeyID: "key",
			},
			expectedErr: false,
		},
		{
			name:         string("unsuppored command:" + plugin.CommandGenerateSignature),
			req:          &plugin.GenerateSignatureRequest{},
			ExpectedResp: nil,
			expectedErr:  true,
		},
		{
			name:         string("unsuppored command:" + plugin.CommandGenerateEnvelope),
			req:          &plugin.GenerateEnvelopeRequest{},
			ExpectedResp: nil,
			expectedErr:  true,
		},
		{
			name:         "unsupported customer command:",
			req:          &customerCommand{},
			ExpectedResp: nil,
			expectedErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := p.Run(context.Background(), tt.req)
			if (err != nil) != tt.expectedErr {
				t.Fatalf("expect builtin runner run with err: %v, got: %v", tt.expectedErr, err)
			}
			if !reflect.DeepEqual(resp, tt.ExpectedResp) {
				t.Fatalf("expect builtin ruuner run result: %v, got: %v", tt.ExpectedResp, resp)
			}
		})
	}
}

func TestProvider_Builtin_Signer(t *testing.T) {
	for _, keyCert := range keyCertPairCollections {
		t.Run(keyCert.keySpecName, func(t *testing.T) {
			p, err := newBuiltinProvider(keyCert.key, keyCert.certs)
			if err != nil {
				t.Fatalf("expect newBuiltInProvider ok, got: %v", err)
			}
			gotCert, err := p.(*builtinProvider).CertificateChain()
			if err != nil {
				t.Fatalf("expect CertificateChain() ok, got: %v", err)
			}
			if !reflect.DeepEqual(gotCert, keyCert.certs) {
				t.Fatalf("CertificateChain() cert changed")
			}

			if gotKey := p.(*builtinProvider).PrivateKey(); !reflect.DeepEqual(gotKey, keyCert.key) {
				t.Fatalf("PrivateKey() key changed")
			}

			if _, _, err = p.Sign(nil); err == nil {
				t.Fatalf("Sign() expect buitin sign method not implemented")
			}

			expectedKeySpec, err := signature.ExtractKeySpec(keyCert.certs[0])
			if err != nil {
				t.Fatalf("extract keySpec failed: %v", err)
			}
			gotKeySpec, err := p.KeySpec()
			if err != nil {
				t.Fatalf("expect keySpec ok, got: %v", err)
			}
			if !reflect.DeepEqual(gotKeySpec, expectedKeySpec) {
				t.Fatalf("KeySpec() keySpec mismatch")
			}
		})
	}
}
