// Copyright (c) Pigeon AS
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/function"
)

var _ function.Function = &SHA256Function{}

// SHA256Function derives key material using HKDF-SHA256.
type SHA256Function struct{}

func NewSHA256Function() function.Function {
	return &SHA256Function{}
}

func (f *SHA256Function) Metadata(_ context.Context, _ function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "sha256"
}

func (f *SHA256Function) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary:     "Derive key material using HKDF-SHA256",
		Description: "Derives deterministic key material from a secret using HKDF-SHA256 (RFC 5869). Returns base64-encoded bytes.",
		Parameters: []function.Parameter{
			function.StringParameter{
				Name:        "secret",
				Description: "Input keying material (IKM), base64-encoded.",
			},
			function.StringParameter{
				Name:        "info",
				Description: "Context and application-specific information (info string).",
			},
			function.Int64Parameter{
				Name:        "length",
				Description: "Number of bytes to derive. Maximum 255 * 32 = 8160.",
			},
		},
		Return: function.StringReturn{},
	}
}

func (f *SHA256Function) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var secretB64, info string
	var length int64

	resp.Error = function.ConcatFuncErrors(resp.Error, req.Arguments.Get(ctx, &secretB64, &info, &length))
	if resp.Error != nil {
		return
	}

	secret, err := base64.StdEncoding.DecodeString(secretB64)
	if err != nil {
		resp.Error = function.NewArgumentFuncError(0, fmt.Sprintf("Invalid secret: must be valid base64: %s", err))
		return
	}

	if length <= 0 || length > 255*32 {
		resp.Error = function.NewArgumentFuncError(2, "Invalid length: must be between 1 and 8160 (255 * SHA-256 hash length).")
		return
	}

	derived, err := deriveHKDF(secret, nil, []byte(info), int(length))
	if err != nil {
		resp.Error = function.NewFuncError(fmt.Sprintf("HKDF derivation failed: %s", err))
		return
	}

	resp.Error = function.ConcatFuncErrors(resp.Error, resp.Result.Set(ctx, base64.StdEncoding.EncodeToString(derived)))
}
