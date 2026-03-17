# Derive a 32-byte key from a base64-encoded secret
data "hkdf_sha256" "example" {
  secret = "dGhpcyBpcyBhIHNlY3JldA==" # base64("this is a secret")
  info   = "example key derivation"
  length = 32
}

# Use the derived key
output "derived_key_b64" {
  value     = data.hkdf_sha256.example.result
  sensitive = true
}

output "derived_key_hex" {
  value     = data.hkdf_sha256.example.result_hex
  sensitive = true
}
