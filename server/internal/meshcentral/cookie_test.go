package meshcentral

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(k) != KeySize || len(KeyHex(k)) != 160 {
		t.Fatalf("key is %d bytes", len(k))
	}
	return k
}

// decodeLikeMeshCentral repeats meshcentral.js decodeCookieAESGCM step by
// step, independently of DecodeCookie.
func decodeLikeMeshCentral(t *testing.T, cookie string, key []byte) map[string]any {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(strings.NewReplacer("@", "+", "$", "/").Replace(cookie))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(key[:32])
	g, _ := cipher.NewGCM(block)
	iv, tag, ct := raw[:12], raw[12:28], raw[28:]
	plain, err := g.Open(nil, iv, append(append([]byte{}, ct...), tag...), nil)
	if err != nil {
		t.Fatalf("MeshCentral could not decrypt the cookie: %v", err)
	}
	var o map[string]any
	if err := json.Unmarshal(plain, &o); err != nil {
		t.Fatal(err)
	}
	return o
}

func TestEncodeCookieFormat(t *testing.T) {
	key := testKey(t)
	now := time.Unix(1_700_000_000, 0)
	c, err := EncodeCookie(map[string]any{"u": "user//x", "a": 3}, key, now)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(c, "+/") {
		t.Errorf("cookie %q still has + or /", c)
	}
	o := decodeLikeMeshCentral(t, c, key)
	if o["u"] != "user//x" || o["a"] != float64(3) || o["time"] != float64(now.Unix()) {
		t.Errorf("payload = %v", o)
	}
	// Each cookie uses a fresh IV.
	c2, _ := EncodeCookie(map[string]any{"u": "user//x", "a": 3}, key, now)
	if c == c2 {
		t.Error("two cookies are identical")
	}
}

func TestEncodeCookieDoesNotChangeInput(t *testing.T) {
	in := map[string]any{"u": "x"}
	if _, err := EncodeCookie(in, testKey(t), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, ok := in["time"]; ok {
		t.Error("EncodeCookie modified its input")
	}
}

func TestShortKeyRejected(t *testing.T) {
	if _, err := EncodeCookie(map[string]any{}, make([]byte, 16), time.Now()); err == nil {
		t.Error("16-byte key accepted for encoding")
	}
	if _, err := DecodeCookie("x", make([]byte, 16), time.Now(), time.Minute); err == nil {
		t.Error("16-byte key accepted for decoding")
	}
}

func TestDecodeCookieExpiry(t *testing.T) {
	key := testKey(t)
	now := time.Unix(1_700_000_000, 0)
	plain, _ := EncodeCookie(map[string]any{"k": "v"}, key, now)
	withExpire, _ := EncodeCookie(map[string]any{"expire": 5}, key, now)
	never, _ := EncodeCookie(map[string]any{"expire": 0}, key, now)

	cases := []struct {
		name    string
		cookie  string
		at      time.Time
		timeout time.Duration
		ok      bool
	}{
		{"fresh", plain, now.Add(time.Minute), 2 * time.Minute, true},
		{"past timeout", plain, now.Add(3 * time.Minute), 2 * time.Minute, false},
		{"slightly in the future", plain, now.Add(-20 * time.Second), 2 * time.Minute, true},
		{"too far in the future", plain, now.Add(-time.Minute), 2 * time.Minute, false},
		{"expire wins over timeout", withExpire, now.Add(4 * time.Minute), time.Minute, true},
		{"past expire", withExpire, now.Add(6 * time.Minute), time.Hour, false},
		{"expire 0 never ends", never, now.Add(1000 * time.Hour), time.Minute, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeCookie(tc.cookie, key, tc.at, tc.timeout)
			if (err == nil) != tc.ok {
				t.Errorf("err = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestDecodeCookieRejectsTampering(t *testing.T) {
	key := testKey(t)
	now := time.Now()
	c, _ := EncodeCookie(map[string]any{"u": "user//x"}, key, now)
	other := testKey(t)
	if _, err := DecodeCookie(c, other, now, time.Minute); !errors.Is(err, ErrBadCookie) {
		t.Errorf("wrong key: %v", err)
	}
	b := []byte(c)
	b[len(b)/2] ^= 1
	if _, err := DecodeCookie(string(b), key, now, time.Minute); !errors.Is(err, ErrBadCookie) {
		t.Errorf("flipped bit: %v", err)
	}
	for _, junk := range []string{"", "!!!", "QUJD"} {
		if _, err := DecodeCookie(junk, key, now, time.Minute); !errors.Is(err, ErrBadCookie) {
			t.Errorf("%q: %v", junk, err)
		}
	}
	// A cookie whose payload has no numeric time is refused, as MeshCentral does.
	block, _ := aes.NewCipher(key[:32])
	g, _ := cipher.NewGCM(block)
	iv := make([]byte, 12)
	sealed := g.Seal(nil, iv, []byte(`{"time":"soon"}`), nil)
	raw := append(append(append([]byte{}, iv...), sealed[len(sealed)-16:]...), sealed[:len(sealed)-16]...)
	if _, err := DecodeCookie(base64.StdEncoding.EncodeToString(raw), key, now, time.Minute); !errors.Is(err, ErrBadCookie) {
		t.Errorf("non-numeric time: %v", err)
	}
	sealed = g.Seal(nil, iv, []byte(`not json`), nil)
	raw = append(append(append([]byte{}, iv...), sealed[len(sealed)-16:]...), sealed[:len(sealed)-16]...)
	if _, err := DecodeCookie(base64.StdEncoding.EncodeToString(raw), key, now, time.Minute); !errors.Is(err, ErrBadCookie) {
		t.Errorf("non-JSON payload: %v", err)
	}
}

func TestLoginToken(t *testing.T) {
	key := testKey(t)
	now := time.Now()
	tok, err := LoginToken(key, UserID("EasyRMM-Abc"), now)
	if err != nil {
		t.Fatal(err)
	}
	o, err := DecodeCookie(tok, key, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if o["u"] != "user//easyrmm-abc" || o["a"] != float64(3) || o["expire"] != float64(1) {
		t.Errorf("token = %v", o)
	}
	if once, _ := o["once"].(string); len(once) != 32 {
		t.Errorf("once = %v", o["once"])
	}
	if _, err := DecodeCookie(tok, key, now.Add(2*time.Minute), time.Hour); err == nil {
		t.Error("login token valid after two minutes")
	}
	tok2, _ := LoginToken(key, UserID("x"), now)
	o2, _ := DecodeCookie(tok2, key, now, time.Hour)
	if o2["once"] == o["once"] {
		t.Error("two tokens share a once value")
	}
}

func TestControlAuthCookie(t *testing.T) {
	key := testKey(t)
	now := time.Now()
	c, err := controlAuth(key, UserID(ServiceAccount), now)
	if err != nil {
		t.Fatal(err)
	}
	o, err := DecodeCookie(c, key, now.Add(59*time.Minute), 60*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if o["userid"] != "user//easyrmm-service" || o["domainid"] != "" {
		t.Errorf("auth cookie = %v", o)
	}
}

func TestAccessRights(t *testing.T) {
	if (Access{}).Rights() != 0 || (Access{}).Any() {
		t.Error("no access must mean no rights")
	}
	all := Access{Desktop: true, Terminal: true, Files: true}.Rights()
	if all&RightRemoteControl == 0 {
		t.Error("remote control missing")
	}
	for _, forbidden := range []uint32{RightEditMesh, RightManageUsers, RightManageDevices, RightAgentConsole, RightNoDesktop, RightNoTerminal, RightNoFiles} {
		if all&forbidden != 0 {
			t.Errorf("full access includes %#x", forbidden)
		}
	}
	for _, restricted := range []uint32{RightNoAMT, RightLimitEvents, RightNoRegistry, RightNoSoftware} {
		if all&restricted == 0 {
			t.Errorf("restriction %#x missing", restricted)
		}
	}
	desk := Access{Desktop: true}.Rights()
	if desk&RightNoDesktop != 0 || desk&RightNoTerminal == 0 || desk&RightNoFiles == 0 {
		t.Errorf("desktop only = %#x", desk)
	}
	files := Access{Files: true}.Rights()
	if files&RightNoDesktop == 0 || files&RightNoTerminal == 0 || files&RightNoFiles != 0 {
		t.Errorf("files only = %#x", files)
	}
}
