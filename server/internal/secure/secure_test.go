package secure

import (
	"bytes"
	"strings"
	"testing"
)

func TestBoxRoundTrip(t *testing.T) {
	var key [32]byte
	copy(key[:], "0123456789abcdef0123456789abcdef")
	box, err := NewBox(key)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := box.Seal("pdns-api-key")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sealed, "v1:") || strings.Contains(sealed, "pdns-api-key") {
		t.Fatalf("unexpected ciphertext %q", sealed)
	}
	plain, err := box.Open(sealed)
	if err != nil || plain != "pdns-api-key" {
		t.Fatalf("Open = %q, %v", plain, err)
	}
	other, _ := box.Seal("pdns-api-key")
	if other == sealed {
		t.Error("nonce reuse: identical ciphertexts")
	}
	var wrong [32]byte
	box2, _ := NewBox(wrong)
	if _, err := box2.Open(sealed); err == nil {
		t.Error("expected failure with the wrong key")
	}
	if _, err := box.Open("v1:" + sealed[3:len(sealed)-2] + "AA"); err == nil {
		t.Error("expected failure for tampered ciphertext")
	}
}

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$") {
		t.Fatalf("unexpected encoding %q", h)
	}
	if !VerifyPassword("correct horse battery staple", h) {
		t.Error("valid password rejected")
	}
	if VerifyPassword("wrong", h) {
		t.Error("invalid password accepted")
	}
	if VerifyPassword("x", "garbage") {
		t.Error("garbage hash accepted")
	}
}

func TestTokens(t *testing.T) {
	a, b := RandomToken(32), RandomToken(32)
	if a == b || len(a) < 40 {
		t.Errorf("weak tokens %q %q", a, b)
	}
	if !bytes.Equal(HashToken(a), HashToken(a)) || bytes.Equal(HashToken(a), HashToken(b)) {
		t.Error("HashToken is not deterministic or collides")
	}
	code := RandomCode(8)
	if len(code) != 11 || code[5] != '-' {
		t.Errorf("unexpected recovery code format %q", code)
	}
	if len(RandomHex(2)) != 4 {
		t.Error("RandomHex length")
	}
}
