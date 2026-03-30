# Derive a 32-byte key using HKDF-SHA256
output "derived_key" {
  value     = provider::hkdf::sha256("dGhpcyBpcyBhIHNlY3JldA==", "example derivation", 32)
  sensitive = true
}
