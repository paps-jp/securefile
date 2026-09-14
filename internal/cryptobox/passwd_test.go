package cryptobox

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestWrapUnwrap(t *testing.T) {
	dek := testKey(t)
	wrapped, err := WrapKey(dek, "correct horse battery staple")
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	if bytes.Contains(wrapped, dek) {
		t.Fatal("wrapped blob contains the plaintext key")
	}

	got, err := UnwrapKey(wrapped, "correct horse battery staple")
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Error("unwrapped key does not match original")
	}

	if _, err := UnwrapKey(wrapped, "wrong password"); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("wrong password: got %v, want ErrWrongPassword", err)
	}
}

// TestWrapParamsAuthenticated checks that the Argon2 cost written into the
// blob cannot be lowered by an attacker to make brute force cheaper.
func TestWrapParamsAuthenticated(t *testing.T) {
	wrapped, err := WrapKey(testKey(t), "pw")
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	tampered := append([]byte(nil), wrapped...)
	tampered[1] = 0
	tampered[2] = 0
	tampered[3] = 0
	tampered[4] = 1 // time = 1 instead of argonTime

	if _, err := UnwrapKey(tampered, "pw"); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("downgraded params: got %v, want ErrWrongPassword", err)
	}
}

func TestGeneratedSecrets(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		k, err := NewDropKey()
		if err != nil {
			t.Fatalf("NewDropKey: %v", err)
		}
		if len(k) != keyLength {
			t.Fatalf("key length %d, want %d", len(k), keyLength)
		}
		if seen[k] {
			t.Fatal("NewDropKey returned a duplicate")
		}
		seen[k] = true

		p, err := NewPassword()
		if err != nil {
			t.Fatalf("NewPassword: %v", err)
		}
		if strings.ContainsAny(p, "0OolI1") {
			t.Errorf("password %q contains an ambiguous character", p)
		}
	}
}
