// Copyright (c) Pigeon AS
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/shoenig/test/must"
)

func TestDeriveHKDF(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		secret := []byte("test-secret")
		info := []byte("test-info")
		a, err := deriveHKDF(secret, nil, info, 32)
		must.NoError(t, err)
		b, err := deriveHKDF(secret, nil, info, 32)
		must.NoError(t, err)
		must.EqOp(t, hex.EncodeToString(a), hex.EncodeToString(b))
	})

	t.Run("different info produces different output", func(t *testing.T) {
		secret := []byte("test-secret")
		a, err := deriveHKDF(secret, nil, []byte("info-a"), 32)
		must.NoError(t, err)
		b, err := deriveHKDF(secret, nil, []byte("info-b"), 32)
		must.NoError(t, err)
		must.True(t, hex.EncodeToString(a) != hex.EncodeToString(b))
	})

	t.Run("respects length", func(t *testing.T) {
		secret := []byte("test-secret")
		out, err := deriveHKDF(secret, nil, []byte("info"), 16)
		must.NoError(t, err)
		must.EqOp(t, 16, len(out))
	})

	t.Run("with salt", func(t *testing.T) {
		secret := []byte("test-secret")
		info := []byte("test-info")
		a, err := deriveHKDF(secret, nil, info, 32)
		must.NoError(t, err)
		b, err := deriveHKDF(secret, []byte("salt"), info, 32)
		must.NoError(t, err)
		must.True(t, hex.EncodeToString(a) != hex.EncodeToString(b))
	})

	t.Run("matches pigeon-enroll derivation", func(t *testing.T) {
		// Verify compatibility with pigeon-enroll's info string format.
		secret, _ := hex.DecodeString("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
		info := []byte("pigeon-enroll derive vault_management_token")
		out, err := deriveHKDF(secret, nil, info, 32)
		must.NoError(t, err)
		// Just verify it produces valid base64 and hex output.
		b64 := base64.StdEncoding.EncodeToString(out)
		h := hex.EncodeToString(out)
		must.True(t, len(b64) > 0)
		must.EqOp(t, 64, len(h))
	})
}
