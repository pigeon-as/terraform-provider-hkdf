# Terraform Provider: HKDF

Derives deterministic key material using [HKDF-SHA256](https://datatracker.ietf.org/doc/html/rfc5869) (RFC 5869).

## Usage

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

## Requirements

- Terraform >= 1.0
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
