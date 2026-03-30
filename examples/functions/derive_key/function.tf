# Derive an Ed25519 private key from an enrollment key using HKDF-SHA256.
# The resulting PEM key can be used with tls_self_signed_cert to create
# a CA certificate that matches pigeon-enroll's DeriveNamedCA output.
output "private_key_pem" {
  value     = provider::hkdf::derive_key(var.enrollment_key_base64, "pigeon-enroll ca nomad key v1", "ed25519")
  sensitive = true
}

# Use with tls_self_signed_cert to create a deterministic CA certificate
resource "tls_self_signed_cert" "nomad_ca" {
  private_key_pem = provider::hkdf::derive_key(var.enrollment_key_base64, "pigeon-enroll ca nomad key v1", "ed25519")

  subject {
    common_name = "nomad"
  }

  validity_period_hours = 876000
  is_ca_certificate     = true
  allowed_uses          = ["cert_signing"]
}
