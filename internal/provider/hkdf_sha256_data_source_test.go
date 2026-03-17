// Copyright (c) Pigeon AS
// SPDX-License-Identifier: MPL-2.0

package provider_test

import (
	"encoding/base64"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccHKDFSHA256DataSource_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "hkdf_sha256" "test" {
  secret = "` + base64.StdEncoding.EncodeToString([]byte("test secret")) + `"
  info   = "test info"
  length = 32
}
`,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"data.hkdf_sha256.test",
						tfjsonpath.New("result"),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownValue(
						"data.hkdf_sha256.test",
						tfjsonpath.New("result_hex"),
						knownvalue.NotNull(),
					),
				},
			},
		},
	})
}

func TestAccHKDFSHA256DataSource_deterministic(t *testing.T) {
	secret := base64.StdEncoding.EncodeToString([]byte("deterministic secret"))
	config := `
data "hkdf_sha256" "a" {
  secret = "` + secret + `"
  info   = "deterministic info"
  length = 32
}

data "hkdf_sha256" "b" {
  secret = "` + secret + `"
  info   = "deterministic info"
  length = 32
}
`
	// Two data sources with identical inputs must produce identical outputs.
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.CompareValuePairs(
						"data.hkdf_sha256.a",
						tfjsonpath.New("result"),
						"data.hkdf_sha256.b",
						tfjsonpath.New("result"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						"data.hkdf_sha256.a",
						tfjsonpath.New("result_hex"),
						"data.hkdf_sha256.b",
						tfjsonpath.New("result_hex"),
						compare.ValuesSame(),
					),
				},
			},
		},
	})
}

func TestAccHKDFSHA256DataSource_resultHexFormat(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "hkdf_sha256" "test" {
  secret = "` + base64.StdEncoding.EncodeToString([]byte("hex test")) + `"
  info   = "hex format"
  length = 16
}
`,
				ConfigStateChecks: []statecheck.StateCheck{
					// result_hex for 16 bytes should be exactly 32 hex chars
					statecheck.ExpectKnownValue(
						"data.hkdf_sha256.test",
						tfjsonpath.New("result_hex"),
						knownvalue.StringRegexp(regexp.MustCompile(`^[0-9a-f]{32}$`)),
					),
				},
			},
		},
	})
}

func TestAccHKDFSHA256DataSource_withSalt(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "hkdf_sha256" "test" {
  secret = "` + base64.StdEncoding.EncodeToString([]byte("salt test")) + `"
  salt   = "` + base64.StdEncoding.EncodeToString([]byte("my salt")) + `"
  info   = "salted derivation"
  length = 32
}
`,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"data.hkdf_sha256.test",
						tfjsonpath.New("result"),
						knownvalue.NotNull(),
					),
				},
			},
		},
	})
}

func TestAccHKDFSHA256DataSource_invalidSecret(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "hkdf_sha256" "test" {
  secret = "not-valid-base64!!!"
  info   = "should fail"
  length = 32
}
`,
				ExpectError: regexp.MustCompile(`Invalid Secret`),
			},
		},
	})
}

func TestAccHKDFSHA256DataSource_invalidLength(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "hkdf_sha256" "test" {
  secret = "` + base64.StdEncoding.EncodeToString([]byte("test")) + `"
  info   = "should fail"
  length = 0
}
`,
				ExpectError: regexp.MustCompile(`Invalid Length`),
			},
		},
	})
}
