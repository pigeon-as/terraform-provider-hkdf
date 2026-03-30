# Terraform Provider: HKDF

Derives deterministic key material using [HKDF-SHA256](https://datatracker.ietf.org/doc/html/rfc5869) (RFC 5869).

## Usage

### Data Source

```hcl
provider "hkdf" {}

data "hkdf_sha256" "example" {
  secret = "dGhpcyBpcyBhIHNlY3JldA==" # base64("this is a secret")
  info   = "my-app token"
  length = 32
}

output "derived_key" {
  value     = data.hkdf_sha256.example.result_hex
  sensitive = true
}
```

### Provider Functions (Terraform 1.8+)

```hcl
# Derive raw bytes (base64)
output "derived_bytes" {
  value     = provider::hkdf::sha256(var.secret, "my-app token", 32)
  sensitive = true
}

# Derive an Ed25519 private key (PEM) — use with tls_self_signed_cert
resource "tls_self_signed_cert" "ca" {
  private_key_pem = provider::hkdf::derive_key(var.secret, "my-app ca key v1", "ed25519")

  subject { common_name = "my-app" }
  validity_period_hours = 876000
  is_ca_certificate     = true
  allowed_uses          = ["cert_signing"]
}
```

## Requirements

- Terraform >= 1.8 (for provider functions), >= 1.0 (for data sources only)
- Go >= 1.25 (building from source)

## Building

```shell
go install
```

## Testing

```shell
make test     # Unit tests
make testacc  # Acceptance tests
```
