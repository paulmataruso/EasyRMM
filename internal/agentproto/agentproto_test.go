package agentproto

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestSignAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	body := []byte(`{"facts":{"hostname":"web-01"}}`)
	h, err := Sign(priv, "dev-1", "post", PathHeartbeat, body, now)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "EasyRMM-Agent device=dev-1, ts=1800000000, nonce=") {
		t.Fatalf("header = %s", h)
	}
	a, err := Parse(h)
	if err != nil {
		t.Fatal(err)
	}
	if a.Device != "dev-1" || a.Timestamp != now.Unix() || !a.Verify(pub, "POST", PathHeartbeat, body) {
		t.Fatalf("parsed = %+v", a)
	}

	// Anything signed is bound: method, target, body, key.
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	for name, ok := range map[string]bool{
		"method": a.Verify(pub, "GET", PathHeartbeat, body),
		"target": a.Verify(pub, "POST", PathHeartbeat+"?x=1", body),
		"body":   a.Verify(pub, "POST", PathHeartbeat, []byte(`{}`)),
		"key":    a.Verify(other, "POST", PathHeartbeat, body),
		"short":  a.Verify(pub[:10], "POST", PathHeartbeat, body),
	} {
		if ok {
			t.Errorf("signature still verifies with a different %s", name)
		}
	}
	tampered := a
	tampered.Timestamp++
	if tampered.Verify(pub, "POST", PathHeartbeat, body) {
		t.Error("signature verifies with a different timestamp")
	}
	tampered = a
	tampered.Nonce = strings.Repeat("A", 24)
	if tampered.Verify(pub, "POST", PathHeartbeat, body) {
		t.Error("signature verifies with a different nonce")
	}

	// Two signatures of the same request differ (fresh nonce).
	h2, _ := Sign(priv, "dev-1", "POST", PathHeartbeat, body, now)
	if h2 == h {
		t.Error("nonce repeated")
	}
}

func TestFresh(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for skew, want := range map[time.Duration]bool{
		0: true, 4 * time.Minute: true, -4 * time.Minute: true,
		5 * time.Minute: false, -6 * time.Minute: false, time.Hour: false,
	} {
		a := Auth{Timestamp: now.Add(skew).Unix()}
		if a.Fresh(now) != want {
			t.Errorf("skew %v: fresh = %v", skew, !want)
		}
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	good, _ := Sign(priv, "d", "GET", "/", nil, time.Now())
	parts := strings.SplitN(strings.TrimPrefix(good, Scheme+" "), ", ", 4)
	sig := parts[3]
	for _, h := range []string{
		"",
		"Bearer abc",
		Scheme + " device=d",
		Scheme + " device=d, ts=1, nonce=AAAAAAAAAAAAAAAAAAAAAAAA",
		Scheme + " device=d, ts=x, nonce=AAAAAAAAAAAAAAAAAAAAAAAA, " + sig,
		Scheme + " device=d, ts=1, nonce=short, " + sig,
		Scheme + " device=d, ts=1, nonce=AAAAAAAAAAAAAAAAAAAAAAAA, sig=AAAA",
		Scheme + " device=d, ts=1, nonce=AAAAAAAAAAAAAAAAAAAAAAAA, " + sig + ", extra=1",
		Scheme + " device=d, device=e, nonce=AAAAAAAAAAAAAAAAAAAAAAAA, " + sig,
		Scheme + " device=, ts=1, nonce=AAAAAAAAAAAAAAAAAAAAAAAA, " + sig,
		Scheme + " device=d, ts=1, nonce=AAAAAAAAAAAAAAAAAAAAAAAA, sig=!!!",
		Scheme + " device=d ts=1",
	} {
		if _, err := Parse(h); err == nil {
			t.Errorf("Parse(%q) accepted", h)
		}
	}
}

func TestMeshNodeKey(t *testing.T) {
	// What `meshagent -nodeid` printed for a real agent, in MeshCentral's
	// encoding. TestAgentEndToEnd (server/internal/remote) checks the
	// conversion against the node id MeshCentral itself reports.
	got, err := MeshNodeKey("284B953F153B329D15BCB32D4FF0D8A8E588030A9D00AE38EA0BDBD50855E59F4CE162723EAA1EBC8878B08ADC51D6C7\n")
	if err != nil {
		t.Fatal(err)
	}
	if got != "node//KEuVPxU7Mp0VvLMtT$DYqOWIAwqdAK446gvb1QhV5Z9M4WJyPqoevIh4sIrcUdbH" {
		t.Errorf("MeshNodeKey = %s", got)
	}
	for _, bad := range []string{"", "abc", strings.Repeat("zz", 48), strings.Repeat("ab", 47)} {
		if _, err := MeshNodeKey(bad); err == nil {
			t.Errorf("MeshNodeKey(%q) accepted", bad)
		}
	}
}

func TestMeshArch(t *testing.T) {
	for in, want := range map[[2]string]int{
		{"windows", "amd64"}: 4, {"windows", "386"}: 3, {"windows", "arm64"}: 43,
		{"linux", "amd64"}: 6, {"linux", "386"}: 5, {"linux", "arm64"}: 26, {"linux", "arm"}: 25,
		{"darwin", "arm64"}: 0, {"plan9", "amd64"}: 0,
	} {
		if got := MeshArch(in[0], in[1]); got != want {
			t.Errorf("MeshArch(%s/%s) = %d, want %d", in[0], in[1], got, want)
		}
	}
}
