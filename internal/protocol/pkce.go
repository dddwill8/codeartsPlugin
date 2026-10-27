package protocol

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"
)

// PKCE returns a S256 code_verifier and code_challenge.
func PKCE() (verifier, challenge string, err error) {
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// RandomHex returns n random bytes as lowercase hex (length 2n).
func RandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// RandomHexOrTime returns n random bytes as hex, falling back to a timestamp.
func RandomHexOrTime(n int) string {
	s, err := RandomHex(n)
	if err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return s
}
