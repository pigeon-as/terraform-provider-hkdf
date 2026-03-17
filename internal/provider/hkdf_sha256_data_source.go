// Copyright (c) Pigeon AS
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/base64"
	"encoding/hex"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &HKDFSHA256DataSource{}

func NewHKDFSHA256DataSource() datasource.DataSource {
	return &HKDFSHA256DataSource{}
}

// HKDFSHA256DataSource derives key material using HKDF-SHA256 (RFC 5869).
type HKDFSHA256DataSource struct{}

// HKDFSHA256DataSourceModel describes the data source data model.
type HKDFSHA256DataSourceModel struct {
	Secret    types.String `tfsdk:"secret"`
	Salt      types.String `tfsdk:"salt"`
	Info      types.String `tfsdk:"info"`
	Length    types.Int64  `tfsdk:"length"`
	Result    types.String `tfsdk:"result"`
	ResultHex types.String `tfsdk:"result_hex"`
}

func (d *HKDFSHA256DataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_sha256"
}

func (d *HKDFSHA256DataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Derives key material using HKDF-SHA256 ([RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869)).",
		Attributes: map[string]schema.Attribute{
			"secret": schema.StringAttribute{
				MarkdownDescription: "Input keying material (IKM), base64-encoded.",
				Required:            true,
				Sensitive:           true,
			},
			"salt": schema.StringAttribute{
				MarkdownDescription: "Optional salt value, base64-encoded. " +
					"If omitted, HKDF uses a zero-filled salt per RFC 5869.",
				Optional: true,
			},
			"info": schema.StringAttribute{
				MarkdownDescription: "Context and application-specific information (info string).",
				Required:            true,
			},
			"length": schema.Int64Attribute{
				MarkdownDescription: "Number of bytes to derive. Maximum 255 * 32 = 8160.",
				Required:            true,
			},
			"result": schema.StringAttribute{
				MarkdownDescription: "Derived key material, base64-encoded.",
				Computed:            true,
				Sensitive:           true,
			},
			"result_hex": schema.StringAttribute{
				MarkdownDescription: "Derived key material, hex-encoded.",
				Computed:            true,
				Sensitive:           true,
			},
		},
	}
}

func (d *HKDFSHA256DataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data HKDFSHA256DataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Decode secret from base64.
	secret, err := base64.StdEncoding.DecodeString(data.Secret.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(
			path.Root("secret"),
			"Invalid Secret",
			"Secret must be valid base64: "+err.Error(),
		)
		return
	}

	// Decode optional salt from base64.
	var salt []byte
	if !data.Salt.IsNull() && !data.Salt.IsUnknown() {
		salt, err = base64.StdEncoding.DecodeString(data.Salt.ValueString())
		if err != nil {
			resp.Diagnostics.AddAttributeError(
				path.Root("salt"),
				"Invalid Salt",
				"Salt must be valid base64: "+err.Error(),
			)
			return
		}
	}

	length := int(data.Length.ValueInt64())
	if length <= 0 || length > 255*32 {
		resp.Diagnostics.AddAttributeError(
			path.Root("length"),
			"Invalid Length",
			"Length must be between 1 and 8160 (255 * SHA-256 hash length).",
		)
		return
	}

	info := []byte(data.Info.ValueString())

	derived, err := deriveHKDF(secret, salt, info, length)
	if err != nil {
		resp.Diagnostics.AddError(
			"HKDF Derivation Failed",
			"Error deriving key material: "+err.Error(),
		)
		return
	}

	data.Result = types.StringValue(base64.StdEncoding.EncodeToString(derived))
	data.ResultHex = types.StringValue(hex.EncodeToString(derived))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
