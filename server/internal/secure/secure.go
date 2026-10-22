// Package secure contains encryption, hashing and token helpers.
package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Box encrypts small secrets (API keys, client secrets) at rest with AES-256-GCM.
type Box struct {
	aead cipher.AEAD
}

func NewBox(key [32]byte) (*Box, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

func (b *Box) Seal(plaintext string) (string, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := b.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return "v1:" + base64.RawStdEncoding.EncodeToString(out), nil
}

func (b *Box) Open(sealed string) (string, error) {
	raw, ok := strings.CutPrefix(sealed, "v1:")
	if !ok {
		return "", errors.New("unsupported ciphertext version")
	}
	data, err := base64.RawStdEncoding.DecodeString(raw)
	if err != nil {
		return "", err
	}
	ns := b.aead.NonceSize()
	if len(data) < ns {
		return "", errors.New("ciphertext too short")
	}
	pt, err := b.aead.Open(nil, data[:ns], data[ns:], nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// RandomToken returns a URL-safe random string with n bytes of entropy.
func RandomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// RandomHex returns n random bytes hex-encoded.
func RandomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// RandomCode returns a human-friendly base32 code (used for recovery codes).
func RandomCode(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	s := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
	if len(s) > 10 {
		s = s[:10]
	}
	return s[:5] + "-" + s[5:]
}

// HashToken is used for bearer secrets that are looked up by hash.
func HashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// Argon2id parameters (OWASP recommended minimums, tuned up slightly).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
)

func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// dummyHash is verified against when a user does not exist so that login
// timing does not reveal account existence.
var dummyHash, _ = HashPassword("flare-timing-equalizer")

func VerifyDummy(password string) { VerifyPassword(password, dummyHash) }
