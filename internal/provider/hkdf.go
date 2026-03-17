// Copyright (c) Pigeon AS
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// deriveHKDF derives length bytes from secret using HKDF-SHA256 with the given info string.
// salt is optional (nil uses a zero-filled salt per RFC 5869).
func deriveHKDF(secret, salt, info []byte, length int) ([]byte, error) {
	r := hkdf.New(sha256.New, secret, salt, info)
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}
