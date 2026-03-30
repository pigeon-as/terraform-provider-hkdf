## 0.1.0 (Unreleased)

FEATURES:

* New data source `hkdf_sha256` — HKDF-SHA256 key derivation with base64 and hex output
* New function `sha256` — HKDF-SHA256 derivation returning base64-encoded bytes (Terraform 1.8+)
* New function `derive_key` — HKDF-SHA256 to PEM-encoded private key, supports Ed25519 (Terraform 1.8+)
