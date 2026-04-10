// Copyright (c) Pigeon AS
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/shoenig/test/must"
)

func TestDeriveEd25519PEM(t *testing.T) {
	secret := []byte("test-secret-32-bytes-exactly!!!!") // 32 bytes

	t.Run("deterministic", func(t *testing.T) {
		info := []byte("pigeon-enroll ca nomad key v1")
		a, err := deriveEd25519PEM(secret, info)
		must.NoError(t, err)
		b, err := deriveEd25519PEM(secret, info)
		must.NoError(t, err)
		must.EqOp(t, a, b)
	})

	t.Run("valid PEM", func(t *testing.T) {
		pemStr, err := deriveEd25519PEM(secret, []byte("test"))
		must.NoError(t, err)
		block, _ := pem.Decode([]byte(pemStr))
		must.NotNil(t, block)
		must.EqOp(t, "PRIVATE KEY", block.Type)
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		must.NoError(t, err)
		_, ok := key.(ed25519.PrivateKey)
		must.True(t, ok)
	})

	t.Run("different info produces different key", func(t *testing.T) {
		a, err := deriveEd25519PEM(secret, []byte("info-a"))
		must.NoError(t, err)
		b, err := deriveEd25519PEM(secret, []byte("info-b"))
		must.NoError(t, err)
		must.True(t, a != b)
	})

	t.Run("compatible with pigeon-enroll info string", func(t *testing.T) {
		// Verify the exact info string format pigeon-enroll uses.
		info := []byte("pigeon-enroll ca nomad key v1")
		pemStr, err := deriveEd25519PEM(secret, info)
		must.NoError(t, err)
		block, _ := pem.Decode([]byte(pemStr))
		must.NotNil(t, block)
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		must.NoError(t, err)
		edKey, ok := key.(ed25519.PrivateKey)
		must.True(t, ok)
		// Verify it's a valid 64-byte Ed25519 key.
		must.EqOp(t, ed25519.PrivateKeySize, len(edKey))
	})
}
