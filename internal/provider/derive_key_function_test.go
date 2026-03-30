// Copyright (c) Pigeon AS
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestDeriveEd25519PEM(t *testing.T) {
	secret := []byte("test-secret-32-bytes-exactly!!!!") // 32 bytes

	t.Run("deterministic", func(t *testing.T) {
		info := []byte("pigeon-enroll ca nomad key v1")
		a, err := deriveEd25519PEM(secret, info)
		if err != nil {
			t.Fatal(err)
		}
		b, err := deriveEd25519PEM(secret, info)
		if err != nil {
			t.Fatal(err)
		}
		if a != b {
			t.Fatal("expected identical PEM outputs")
		}
	})

	t.Run("valid PEM", func(t *testing.T) {
		pemStr, err := deriveEd25519PEM(secret, []byte("test"))
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode([]byte(pemStr))
		if block == nil {
			t.Fatal("expected valid PEM block")
		}
		if block.Type != "PRIVATE KEY" {
			t.Fatalf("PEM type = %q, want \"PRIVATE KEY\"", block.Type)
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			t.Fatalf("parse PKCS8: %v", err)
		}
		if _, ok := key.(ed25519.PrivateKey); !ok {
			t.Fatalf("expected ed25519.PrivateKey, got %T", key)
		}
	})

	t.Run("different info produces different key", func(t *testing.T) {
		a, err := deriveEd25519PEM(secret, []byte("info-a"))
		if err != nil {
			t.Fatal(err)
		}
		b, err := deriveEd25519PEM(secret, []byte("info-b"))
		if err != nil {
			t.Fatal(err)
		}
		if a == b {
			t.Fatal("expected different PEM outputs for different info")
		}
	})

	t.Run("compatible with pigeon-enroll info string", func(t *testing.T) {
		// Verify the exact info string format pigeon-enroll uses.
		info := []byte("pigeon-enroll ca nomad key v1")
		pemStr, err := deriveEd25519PEM(secret, info)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode([]byte(pemStr))
		if block == nil {
			t.Fatal("expected valid PEM block")
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			t.Fatalf("parse PKCS8: %v", err)
		}
		edKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			t.Fatal("expected ed25519.PrivateKey")
		}
		// Verify it's a valid 64-byte Ed25519 key.
		if len(edKey) != ed25519.PrivateKeySize {
			t.Fatalf("key size = %d, want %d", len(edKey), ed25519.PrivateKeySize)
		}
	})
}
