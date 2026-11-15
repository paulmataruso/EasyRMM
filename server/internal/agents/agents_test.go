package agents

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

func TestCleanFacts(t *testing.T) {
	f, err := cleanFacts(agentproto.Facts{
		Hostname: "  web\x00-01\n", OS: strings.Repeat("é", 600), Platform: "beos", Arch: "amd64", AgentVersion: "1.0\xff",
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.hostname != "web-01" || len([]rune(f.os)) != 500 || f.platform != "other" || f.version != "1.0" {
		t.Errorf("cleaned = %+v", f)
	}
	for _, p := range []string{"windows", "linux", "macos"} {
		if f, _ := cleanFacts(agentproto.Facts{Hostname: "h", Platform: p}); f.platform != p {
			t.Errorf("platform %s became %s", p, f.platform)
		}
	}
	if _, err := cleanFacts(agentproto.Facts{Hostname: "\t"}); err == nil {
		t.Error("blank hostname accepted")
	}
	if _, err := cleanFacts(agentproto.Facts{Hostname: "h", MeshNodeID: "abc"}); err == nil {
		t.Error("malformed node id accepted")
	}
}

func TestTokenStatus(t *testing.T) {
	now := time.Now()
	two := 2
	for _, c := range []struct {
		revoked bool
		expires time.Time
		max     *int
		uses    int
		want    TokenStatus
	}{
		{false, now.Add(time.Hour), nil, 5, TokenActive},
		{false, now.Add(time.Hour), &two, 1, TokenActive},
		{false, now.Add(time.Hour), &two, 2, TokenUsedUp},
		{false, now, nil, 0, TokenExpired},
		{true, now.Add(time.Hour), nil, 0, TokenRevoked},
	} {
		if got := tokenStatus(c.revoked, c.expires, c.max, c.uses, now); got != c.want {
			t.Errorf("%+v: %s", c, got)
		}
	}
}

func TestTokenInput(t *testing.T) {
	zero, many := 0, MaxTokenUses+1
	for _, in := range []TokenInput{
		{Name: "", ExpiresInDays: 1},
		{Name: strings.Repeat("x", 201), ExpiresInDays: 1},
		{Name: "x", ExpiresInDays: 0},
		{Name: "x", ExpiresInDays: MaxTokenDays + 1},
		{Name: "x", ExpiresInDays: 1, MaxUses: &zero},
		{Name: "x", ExpiresInDays: 1, MaxUses: &many},
	} {
		if err := in.normalize(); err == nil {
			t.Errorf("%+v accepted", in)
		}
	}
	in := TokenInput{Name: "  Office  ", ExpiresInDays: 90}
	if err := in.normalize(); err != nil || in.Name != "Office" {
		t.Errorf("normalize = %q, %v", in.Name, err)
	}
	secret, hash, err := newTokenSecret()
	if err != nil || !strings.HasPrefix(secret, agentproto.TokenPrefix) || len(hash) != 32 || string(hashToken(secret)) != string(hash) {
		t.Errorf("secret %q", secret)
	}
}

func TestBuilds(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"easyrmm-agent-linux-arm64":        "a",
		"easyrmm-agent-linux-amd64":        "bb",
		"easyrmm-agent-linux-amd64.exe":    "linux with .exe: ignored",
		"easyrmm-agent-windows-386.exe":    "ccc",
		"easyrmm-agent-darwin-arm64":       "unsupported: ignored",
		"notes.txt":                        "ignored",
		"easyrmm-agent-windows-amd64.exe~": "ignored",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "easyrmm-agent-linux-386"), 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := LoadBuilds(dir)
	if err != nil {
		t.Fatal(err)
	}
	list := b.List()
	var names []string
	for _, it := range list {
		names = append(names, it.OS+"/"+it.Arch+"="+it.File)
	}
	if strings.Join(names, ",") != "linux/amd64=easyrmm-agent-linux-amd64,linux/arm64=easyrmm-agent-linux-arm64,windows/386=easyrmm-agent-windows-386.exe" {
		t.Fatalf("builds = %v", names)
	}
	f, it, err := b.Open("easyrmm-agent-linux-amd64")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(f)
	_ = f.Close()
	if string(body) != "bb" || it.Size != 2 || it.ModTime().IsZero() {
		t.Errorf("open = %q %+v", body, it)
	}
	if _, _, err := b.Open("notes.txt"); err == nil {
		t.Error("a file that is not a build was served")
	}
	if !strings.Contains(b.Checksums(), it.SHA256+"  easyrmm-agent-linux-amd64\n") {
		t.Errorf("checksums = %q", b.Checksums())
	}

	for _, d := range []string{"", filepath.Join(dir, "missing")} {
		empty, err := LoadBuilds(d)
		if err != nil || len(empty.List()) != 0 || empty.Checksums() != "" {
			t.Errorf("LoadBuilds(%q) = %v, %v", d, empty, err)
		}
	}
	if _, err := LoadBuilds(filepath.Join(dir, "notes.txt")); err == nil {
		t.Error("a file as the build directory was accepted")
	}
}
