// Package meshcentral talks to the MeshCentral server that provides remote
// desktop, terminal and file access (ADR-0004, ADR-0005).
//
// It contains three pieces, each matching MeshCentral 1.3's own code:
//
//   - cookies: the AES-256-GCM cookie format MeshCentral uses for login
//     tokens and WebSocket authentication (meshcentral.js encodeCookie);
//   - the config.json EasyRMM generates for its MeshCentral container;
//   - a client for MeshCentral's control.ashx WebSocket, used to manage
//     device groups, users and their rights.
package meshcentral

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// KeySize is the length of MeshCentral's loginCookieEncryptionKey. MeshCentral
// rejects any other length; AES-256-GCM cookies use its first 32 bytes.
const KeySize = 80

// Rights MeshCentral attaches to a cookie's "a" field. 3 is a login cookie.
const cookieLogin = 3

// LoginTokenLifetime is how long a login token stays valid. MeshCentral
// expresses expiry in whole minutes; tokens are also single use.
const LoginTokenLifetime = time.Minute

// cookieClockSkew is how far in the future MeshCentral tolerates a cookie's
// creation time.
const cookieClockSkew = 30 * time.Second

// ErrBadCookie reports a cookie that does not decrypt, is malformed or has
// expired.
var ErrBadCookie = errors.New("meshcentral: invalid or expired cookie")

// NewKey returns a fresh random loginCookieEncryptionKey.
func NewKey() ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// KeyHex encodes a key the way config.json expects it.
func KeyHex(key []byte) string { return hex.EncodeToString(key) }

func gcm(key []byte) (cipher.AEAD, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("meshcentral: cookie key is %d bytes, need at least 32", len(key))
	}
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// EncodeCookie produces a cookie MeshCentral accepts: the JSON payload plus a
// creation time, sealed with AES-256-GCM under the first 32 bytes of key, as
// base64(iv ‖ tag ‖ ciphertext) with '+' and '/' replaced by '@' and '$'.
func EncodeCookie(payload map[string]any, key []byte, now time.Time) (string, error) {
	aead, err := gcm(key)
	if err != nil {
		return "", err
	}
	o := make(map[string]any, len(payload)+1)
	for k, v := range payload {
		o[k] = v
	}
	o["time"] = now.Unix()
	plain, err := json.Marshal(o)
	if err != nil {
		return "", err
	}
	iv := make([]byte, aead.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	sealed := aead.Seal(nil, iv, plain, nil) // ciphertext ‖ tag
	ct, tag := sealed[:len(sealed)-aead.Overhead()], sealed[len(sealed)-aead.Overhead():]
	raw := make([]byte, 0, len(iv)+len(tag)+len(ct))
	raw = append(append(append(raw, iv...), tag...), ct...)
	return cookieReplacer.Replace(base64.StdEncoding.EncodeToString(raw)), nil
}

var (
	cookieReplacer   = strings.NewReplacer("+", "@", "/", "$")
	cookieUnreplacer = strings.NewReplacer("@", "+", "$", "/")
)

// DecodeCookie reverses EncodeCookie and applies MeshCentral's expiry rules:
// a numeric "expire" field (minutes, 0 meaning never) wins over timeout, and
// creation times up to 30 seconds in the future are tolerated. It exists so
// tests and diagnostics can check what MeshCentral will see.
func DecodeCookie(cookie string, key []byte, now time.Time, timeout time.Duration) (map[string]any, error) {
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(cookieUnreplacer.Replace(cookie))
	if err != nil || len(raw) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrBadCookie
	}
	iv, tag, ct := raw[:aead.NonceSize()], raw[aead.NonceSize():aead.NonceSize()+aead.Overhead()], raw[aead.NonceSize()+aead.Overhead():]
	plain, err := aead.Open(nil, iv, append(append([]byte{}, ct...), tag...), nil)
	if err != nil {
		return nil, ErrBadCookie
	}
	var o map[string]any
	if err := json.Unmarshal(plain, &o); err != nil {
		return nil, ErrBadCookie
	}
	created, ok := o["time"].(float64)
	if !ok {
		return nil, ErrBadCookie
	}
	age := now.Sub(time.Unix(int64(created), 0))
	if exp, ok := o["expire"].(float64); ok {
		if exp != 0 {
			timeout = time.Duration(exp) * time.Minute
		} else {
			timeout = -1
		}
	}
	if age < -cookieClockSkew || (timeout >= 0 && age > timeout) {
		return nil, ErrBadCookie
	}
	return o, nil
}

// UserID returns the MeshCentral user id for an account name in the default
// domain.
func UserID(name string) string { return "user//" + strings.ToLower(name) }

// LoginToken returns a single-use login token for the user, valid for one
// minute, for the ?login= parameter of MeshCentral's web interface.
func LoginToken(key []byte, userID string, now time.Time) (string, error) {
	once := make([]byte, 16)
	if _, err := rand.Read(once); err != nil {
		return "", err
	}
	return EncodeCookie(map[string]any{
		"u":      userID,
		"a":      cookieLogin,
		"expire": int(LoginTokenLifetime / time.Minute),
		"once":   hex.EncodeToString(once),
	}, key, now)
}

// controlAuth returns the ?auth= cookie that authenticates a control.ashx
// WebSocket as userID. MeshCentral accepts it for 60 minutes; it is only
// used while connecting.
func controlAuth(key []byte, userID string, now time.Time) (string, error) {
	return EncodeCookie(map[string]any{"userid": userID, "domainid": ""}, key, now)
}
