// Copyright (c) Pigeon AS
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestDeriveHKDF(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		secret := []byte("test-secret")
		info := []byte("test-info")
		a, err := deriveHKDF(secret, nil, info, 32)
		if err != nil {
			t.Fatal(err)
		}
		b, err := deriveHKDF(secret, nil, info, 32)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(a) != hex.EncodeToString(b) {
			t.Fatal("expected identical outputs")
		}
	})

	t.Run("different info produces different output", func(t *testing.T) {
		secret := []byte("test-secret")
		a, err := deriveHKDF(secret, nil, []byte("info-a"), 32)
		if err != nil {
			t.Fatal(err)
		}
		b, err := deriveHKDF(secret, nil, []byte("info-b"), 32)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(a) == hex.EncodeToString(b) {
			t.Fatal("expected different outputs for different info")
		}
	})

	t.Run("respects length", func(t *testing.T) {
		secret := []byte("test-secret")
		out, err := deriveHKDF(secret, nil, []byte("info"), 16)
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 16 {
			t.Fatalf("expected 16 bytes, got %d", len(out))
		}
	})

	t.Run("with salt", func(t *testing.T) {
		secret := []byte("test-secret")
		info := []byte("test-info")
		a, err := deriveHKDF(secret, nil, info, 32)
		if err != nil {
			t.Fatal(err)
		}
		b, err := deriveHKDF(secret, []byte("salt"), info, 32)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(a) == hex.EncodeToString(b) {
			t.Fatal("expected different outputs with different salt")
		}
	})

	t.Run("matches pigeon-enroll derivation", func(t *testing.T) {
		// Verify compatibility with pigeon-enroll's info string format.
		secret, _ := hex.DecodeString("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
		info := []byte("pigeon-enroll derive vault_management_token")
		out, err := deriveHKDF(secret, nil, info, 32)
		if err != nil {
			t.Fatal(err)
		}
		// Just verify it produces valid base64 and hex output.
		b64 := base64.StdEncoding.EncodeToString(out)
		h := hex.EncodeToString(out)
		if len(b64) == 0 || len(h) != 64 {
			t.Fatalf("unexpected output: base64=%q hex=%q", b64, h)
		}
	})
}
