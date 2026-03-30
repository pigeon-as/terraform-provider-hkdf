// Copyright (c) Pigeon AS
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/function"
)

var _ function.Function = &DeriveKeyFunction{}

// DeriveKeyFunction derives a cryptographic key from a secret using HKDF-SHA256
// and returns it as a PEM-encoded private key.
type DeriveKeyFunction struct{}

func NewDeriveKeyFunction() function.Function {
	return &DeriveKeyFunction{}
}

func (f *DeriveKeyFunction) Metadata(_ context.Context, _ function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "derive_key"
}

func (f *DeriveKeyFunction) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary:     "Derive a cryptographic key using HKDF-SHA256",
		Description: "Derives a deterministic cryptographic key from a secret using HKDF-SHA256 (RFC 5869) and returns it as a PEM-encoded private key. Supported algorithms: ed25519.",
		Parameters: []function.Parameter{
			function.StringParameter{
				Name:        "secret",
				Description: "Input keying material (IKM), base64-encoded.",
			},
			function.StringParameter{
				Name:        "info",
				Description: "Context and application-specific information (info string).",
			},
			function.StringParameter{
				Name:        "algorithm",
				Description: "Key algorithm. Supported: \"ed25519\".",
			},
		},
		Return: function.StringReturn{},
	}
}

func (f *DeriveKeyFunction) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var secretB64, info, algorithm string

	resp.Error = function.ConcatFuncErrors(resp.Error, req.Arguments.Get(ctx, &secretB64, &info, &algorithm))
	if resp.Error != nil {
		return
	}

	secret, err := base64.StdEncoding.DecodeString(secretB64)
	if err != nil {
		resp.Error = function.NewArgumentFuncError(0, fmt.Sprintf("Invalid secret: must be valid base64: %s", err))
		return
	}

	switch algorithm {
	case "ed25519":
		keyPEM, err := deriveEd25519PEM(secret, []byte(info))
		if err != nil {
			resp.Error = function.NewFuncError(fmt.Sprintf("Key derivation failed: %s", err))
			return
		}
		resp.Error = function.ConcatFuncErrors(resp.Error, resp.Result.Set(ctx, keyPEM))
	default:
		resp.Error = function.NewArgumentFuncError(2, fmt.Sprintf("Unsupported algorithm %q. Supported: \"ed25519\".", algorithm))
	}
}

// deriveEd25519PEM derives an Ed25519 private key from secret+info via HKDF-SHA256
// and returns it as a PEM-encoded PKCS8 private key.
func deriveEd25519PEM(secret, info []byte) (string, error) {
	seed, err := deriveHKDF(secret, nil, info, ed25519.SeedSize)
	if err != nil {
		return "", fmt.Errorf("derive seed: %w", err)
	}

	key := ed25519.NewKeyFromSeed(seed)

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("marshal key: %w", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}
