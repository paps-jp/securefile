package cryptobox

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Seal encrypts a small value (a filename, a note) under key. The nonce is
// prepended to the returned blob.
//
// Filenames go through here rather than being stored in the clear because a
// filename is often the most sensitive part of a transfer: "settlement-draft"
// or a person's name in a document title discloses plenty on its own, even if
// the bytes stay encrypted.
func Seal(key, plaintext []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	n := make([]byte, nonceSize)
	if _, err := rand.Read(n); err != nil {
		return nil, fmt.Errorf("cryptobox: generate nonce: %w", err)
	}
	return aead.Seal(n, n, plaintext, nil), nil
}

// Open reverses Seal.
func Open(key, blob []byte) ([]byte, error) {
	if len(blob) < nonceSize+TagSize {
		return nil, ErrCorrupt
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	out, err := aead.Open(nil, blob[:nonceSize], blob[nonceSize:], nil)
	if err != nil {
		return nil, ErrCorrupt
	}
	return out, nil
}

// DeriveFromToken stretches a high-entropy token into a key with HKDF.
//
// Unlike a user-chosen password, a generated token already carries far more
// entropy than an attacker can search, so there is nothing for a slow KDF to
// buy here — and upload chunks call this on every request, where Argon2 would
// cost more than the encryption itself.
func DeriveFromToken(token, purpose string) ([]byte, error) {
	r := hkdf.New(sha256.New, []byte(token), nil, []byte(purpose))
	k := make([]byte, KeySize)
	if _, err := io.ReadFull(r, k); err != nil {
		return nil, fmt.Errorf("cryptobox: derive from token: %w", err)
	}
	return k, nil
}

// WrapKeyWithToken seals dek under a key derived from a generated token. It is
// the fast counterpart to WrapKey, for secrets the server itself issued.
func WrapKeyWithToken(dek []byte, token, purpose string) ([]byte, error) {
	k, err := DeriveFromToken(token, purpose)
	if err != nil {
		return nil, err
	}
	return Seal(k, dek)
}

// UnwrapKeyWithToken reverses WrapKeyWithToken.
func UnwrapKeyWithToken(wrapped []byte, token, purpose string) ([]byte, error) {
	k, err := DeriveFromToken(token, purpose)
	if err != nil {
		return nil, err
	}
	dek, err := Open(k, wrapped)
	if err != nil {
		return nil, ErrWrongPassword
	}
	if len(dek) != KeySize {
		return nil, ErrWrongPassword
	}
	return dek, nil
}
