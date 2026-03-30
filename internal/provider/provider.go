// Copyright (c) Pigeon AS
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

var _ provider.Provider = &HKDFProvider{}
var _ provider.ProviderWithFunctions = &HKDFProvider{}

// HKDFProvider implements the hkdf provider.
type HKDFProvider struct {
	version string
}

func (p *HKDFProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "hkdf"
	resp.Version = p.version
}

func (p *HKDFProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Derives deterministic key material using HKDF-SHA256 ([RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869)).",
	}
}

func (p *HKDFProvider) Configure(_ context.Context, _ provider.ConfigureRequest, _ *provider.ConfigureResponse) {
	// No provider configuration needed. Key derivation is self-contained.
}

func (p *HKDFProvider) Resources(_ context.Context) []func() resource.Resource {
	return nil
}

func (p *HKDFProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewHKDFSHA256DataSource,
	}
}

func (p *HKDFProvider) Functions(_ context.Context) []func() function.Function {
	return []func() function.Function{
		NewSHA256Function,
		NewDeriveKeyFunction,
	}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &HKDFProvider{
			version: version,
		}
	}
}
