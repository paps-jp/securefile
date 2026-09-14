package cryptobox

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// ErrWrongPassword is returned when a wrapped key cannot be unwrapped. It is
// the only signal the server gives about password correctness.
var ErrWrongPassword = errors.New("cryptobox: wrong password")

// Argon2id parameters. They are written into every wrapped key, so raising
// them later does not invalidate keys wrapped under the old cost.
const (
	argonTime    uint32 = 3
	argonMemory  uint32 = 64 * 1024 // 64 MiB
	argonThreads uint8  = 4
	saltSize            = 16
	wrapVersion  byte   = 1
)

// deriveKEK stretches a password into a key-encryption key.
func deriveKEK(password string, salt []byte, time, memory uint32, threads uint8) []byte {
	return argon2.IDKey([]byte(password), salt, time, memory, threads, KeySize)
}

// WrapKey encrypts dek under a key derived from password.
//
// The data encryption key is never stored in the clear and never derived from
// anything the server keeps. Without the password — which only the uploader
// and whoever they share it with ever see — the stored bytes cannot be
// decrypted, including by an operator with full access to the host.
func WrapKey(dek []byte, password string) ([]byte, error) {
	if len(dek) != KeySize {
		return nil, fmt.Errorf("cryptobox: dek must be %d bytes, got %d", KeySize, len(dek))
	}
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("cryptobox: generate salt: %w", err)
	}
	kek := deriveKEK(password, salt, argonTime, argonMemory, argonThreads)
	aead, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	n := make([]byte, nonceSize)
	if _, err := rand.Read(n); err != nil {
		return nil, fmt.Errorf("cryptobox: generate nonce: %w", err)
	}

	out := make([]byte, 0, 1+4+4+1+saltSize+nonceSize+KeySize+TagSize)
	out = append(out, wrapVersion)
	out = binary.BigEndian.AppendUint32(out, argonTime)
	out = binary.BigEndian.AppendUint32(out, argonMemory)
	out = append(out, argonThreads)
	out = append(out, salt...)
	out = append(out, n...)
	// The parameter header is authenticated as additional data, so an attacker
	// cannot downgrade the Argon2 cost of a stored key.
	return aead.Seal(out, n, dek, out[:1+4+4+1+saltSize]), nil
}

// UnwrapKey recovers a data encryption key from a blob produced by WrapKey.
func UnwrapKey(wrapped []byte, password string) ([]byte, error) {
	const headLen = 1 + 4 + 4 + 1 + saltSize
	if len(wrapped) < headLen+nonceSize+TagSize {
		return nil, ErrWrongPassword
	}
	if wrapped[0] != wrapVersion {
		return nil, fmt.Errorf("cryptobox: unknown wrap version %d", wrapped[0])
	}
	time := binary.BigEndian.Uint32(wrapped[1:5])
	memory := binary.BigEndian.Uint32(wrapped[5:9])
	threads := wrapped[9]
	salt := wrapped[10:headLen]
	n := wrapped[headLen : headLen+nonceSize]
	ct := wrapped[headLen+nonceSize:]

	kek := deriveKEK(password, salt, time, memory, threads)
	aead, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	dek, err := aead.Open(nil, n, ct, wrapped[:headLen])
	if err != nil {
		return nil, ErrWrongPassword
	}
	if subtle.ConstantTimeEq(int32(len(dek)), int32(KeySize)) != 1 {
		return nil, ErrWrongPassword
	}
	return dek, nil
}
