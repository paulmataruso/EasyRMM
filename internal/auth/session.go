package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const sessionTokenBytes = 32

func GenerateSessionToken() (token string, hash string, err error) {
	b := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generating token: %w", err)
	}
	token = hex.EncodeToString(b)
	h := sha256.Sum256([]byte(token))
	hash = hex.EncodeToString(h[:])
	return token, hash, nil
}

func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
