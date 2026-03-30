// Copyright (c) Pigeon AS
// SPDX-License-Identifier: MPL-2.0

package provider_test

import (
	"encoding/base64"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

func TestSHA256Function_basic(t *testing.T) {
	t.Parallel()
	secret := base64.StdEncoding.EncodeToString([]byte("test secret"))

	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_8_0),
		},
		ProtoV6ProviderFactories: testProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
output "result" {
  value = provider::hkdf::sha256("` + secret + `", "test info", 32)
}
`,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectKnownOutputValue("result", knownvalue.NotNull()),
					},
				},
			},
		},
	})
}

func TestSHA256Function_invalidBase64(t *testing.T) {
	t.Parallel()
	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_8_0),
		},
		ProtoV6ProviderFactories: testProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
output "result" {
  value = provider::hkdf::sha256("not-valid-base64!!!", "info", 32)
}
`,
				ExpectError: regexp.MustCompile(`Invalid secret`),
			},
		},
	})
}

func TestDeriveKeyFunction_ed25519(t *testing.T) {
	t.Parallel()
	secret := base64.StdEncoding.EncodeToString([]byte("test-secret-for-key-derivation!!"))

	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_8_0),
		},
		ProtoV6ProviderFactories: testProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
output "key" {
  value     = provider::hkdf::derive_key("` + secret + `", "pigeon-enroll ca nomad key v1", "ed25519")
  sensitive = true
}
`,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectKnownOutputValue("key", knownvalue.NotNull()),
					},
				},
			},
		},
	})
}

func TestDeriveKeyFunction_unsupportedAlgorithm(t *testing.T) {
	t.Parallel()
	secret := base64.StdEncoding.EncodeToString([]byte("test secret"))

	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_8_0),
		},
		ProtoV6ProviderFactories: testProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
output "key" {
  value = provider::hkdf::derive_key("` + secret + `", "info", "rsa")
}
`,
				ExpectError: regexp.MustCompile(`Unsupported algorithm`),
			},
		},
	})
}

func TestAccDeriveKeyFunction_withTLSSelfSignedCert(t *testing.T) {
	t.Parallel()
	secret := base64.StdEncoding.EncodeToString([]byte("test-secret-for-tls-integration!"))

	resource.Test(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_8_0),
		},
		ProtoV6ProviderFactories: testProtoV6ProviderFactories,
		ExternalProviders: map[string]resource.ExternalProvider{
			"tls": {Source: "hashicorp/tls"},
		},
		Steps: []resource.TestStep{
			{
				Config: `
resource "tls_self_signed_cert" "ca" {
  private_key_pem = provider::hkdf::derive_key(
    "` + secret + `",
    "pigeon-enroll ca nomad key v1",
    "ed25519"
  )
  subject {
    common_name = "nomad"
  }
  validity_period_hours = 876000
  is_ca_certificate     = true
  allowed_uses          = ["cert_signing"]
}

output "cert" {
  value = tls_self_signed_cert.ca.cert_pem
}
`,
				Check: resource.TestCheckResourceAttrSet("tls_self_signed_cert.ca", "cert_pem"),
			},
		},
	})
}
