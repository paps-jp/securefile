package cryptobox

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// Alphabets deliberately exclude characters that are easy to confuse when a
// link or password is read aloud, retyped from a screenshot, or handled by a
// font that renders 0/O and 1/l/I alike. Recipients of this service often
// receive the password through a different channel than the link, so the
// characters have to survive being copied by hand.
const (
	keyAlphabet      = "23456789abcdefghjkmnpqrstuvwxyz"
	passwordAlphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz"

	keyLength      = 14 // ~69 bits
	passwordLength = 16 // ~92 bits
)

// randomString draws n characters uniformly from alphabet using rejection-free
// big.Int selection, so no character is more likely than any other.
func randomString(alphabet string, n int) (string, error) {
	max := big.NewInt(int64(len(alphabet)))
	out := make([]byte, n)
	for i := range out {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("cryptobox: random: %w", err)
		}
		out[i] = alphabet[v.Int64()]
	}
	return string(out), nil
}

// NewDropKey returns the unguessable component of a share URL.
func NewDropKey() (string, error) { return randomString(keyAlphabet, keyLength) }

// NewPassword returns a generated share password.
func NewPassword() (string, error) { return randomString(passwordAlphabet, passwordLength) }

// NewToken returns an opaque session token.
func NewToken() (string, error) { return randomString(passwordAlphabet, 32) }

// NewManageToken returns the sender's management-link secret. It is the same
// strength as a session token but named for its distinct purpose.
func NewManageToken() (string, error) { return randomString(passwordAlphabet, 32) }

// ManageTokenHash returns the SHA-256 of a management token. Only this hash is
// stored, and the sender's link is resolved by matching it, so a database dump
// discloses no token that would let someone track or delete a share.
func ManageTokenHash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}
