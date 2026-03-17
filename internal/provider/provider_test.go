// Copyright (c) Pigeon AS
// SPDX-License-Identifier: MPL-2.0

package provider_test

import (
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"

	"github.com/pigeon-as/terraform-provider-hkdf/internal/provider"
)

var testProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"hkdf": providerserver.NewProtocol6WithError(provider.New("test")()),
}
