# Derive an Ed25519 private key using HKDF-SHA256
output "private_key_pem" {
  value     = provider::hkdf::derive_key(var.secret, "my-app ca key v1", "ed25519")
  sensitive = true
}

# Use with tls_self_signed_cert to create a deterministic CA certificate
resource "tls_self_signed_cert" "ca" {
  private_key_pem = provider::hkdf::derive_key(var.secret, "my-app ca key v1", "ed25519")

  subject {
    common_name = "my-app"
  }

  validity_period_hours = 876000
  is_ca_certificate     = true
  allowed_uses          = ["cert_signing"]
}
