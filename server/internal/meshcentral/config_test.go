package meshcentral

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validConfig(t *testing.T) ServerConfig {
	return ServerConfig{
		Hostname: "mesh.rmm.example.com", Listen: "127.0.0.1:14430", PublicPort: 443,
		TrustedProxy: "127.0.0.1", FramingOrigin: "https://rmm.example.com",
		CertURL: "https://127.0.0.1:443", LoginKey: testKey(t), SessionKey: strings.Repeat("s", 64),
	}
}

func TestRenderConfig(t *testing.T) {
	cfg := validConfig(t)
	out, err := cfg.Render()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Settings map[string]any            `json:"settings"`
		Domains  map[string]map[string]any `json:"domains"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	s := doc.Settings
	want := map[string]any{
		"cert": "mesh.rmm.example.com", "port": float64(14430), "portBind": "127.0.0.1",
		"aliasPort": float64(443), "redirPort": float64(0), "mpsPort": float64(0),
		"tlsOffload": "127.0.0.1", "trustedProxy": "127.0.0.1", "WANonly": true,
		"webRTC": false, "amtManager": false, "selfUpdate": false, "exactPorts": true,
		"loginCookieEncryptionKey": KeyHex(cfg.LoginKey),
	}
	for k, v := range want {
		if s[k] != v {
			t.Errorf("settings.%s = %v, want %v", k, s[k], v)
		}
	}
	if o, _ := s["allowedFramingOrigins"].([]any); len(o) != 1 || o[0] != "https://rmm.example.com" {
		t.Errorf("framing origins = %v", s["allowedFramingOrigins"])
	}
	d := doc.Domains[""]
	if d["newAccounts"] != false || d["guestDeviceSharing"] != false || d["certUrl"] != "https://127.0.0.1:443" || d["lockAgentDownload"] != true {
		t.Errorf("domain = %v", d)
	}
	if pr, _ := d["passwordRequirements"].(map[string]any); pr["loginTokens"] != false {
		t.Errorf("user-created login tokens are not disabled: %v", d["passwordRequirements"])
	}
}

func TestConfigValidation(t *testing.T) {
	for name, mutate := range map[string]func(*ServerConfig){
		"no hostname":       func(c *ServerConfig) { c.Hostname = "" },
		"public listen":     func(c *ServerConfig) { c.Listen = "0.0.0.0:14430" },
		"bad listen":        func(c *ServerConfig) { c.Listen = "localhost" },
		"bad port":          func(c *ServerConfig) { c.Listen = "127.0.0.1:99999" },
		"public port":       func(c *ServerConfig) { c.PublicPort = 0 },
		"proxy not an IP":   func(c *ServerConfig) { c.TrustedProxy = "edge" },
		"http origin":       func(c *ServerConfig) { c.FramingOrigin = "http://rmm.example.com" },
		"origin with path":  func(c *ServerConfig) { c.FramingOrigin = "https://rmm.example.com/app" },
		"cert URL scheme":   func(c *ServerConfig) { c.CertURL = "ftp://x" },
		"short login key":   func(c *ServerConfig) { c.LoginKey = c.LoginKey[:32] },
		"short session key": func(c *ServerConfig) { c.SessionKey = "short" },
	} {
		t.Run(name, func(t *testing.T) {
			c := validConfig(t)
			mutate(&c)
			if _, err := c.Render(); err == nil {
				t.Error("invalid configuration rendered")
			}
		})
	}
}

func TestWriteConfig(t *testing.T) {
	dir := t.TempDir()
	changed, err := WriteConfig(dir, []byte("one"))
	if err != nil || !changed {
		t.Fatalf("first write: changed=%v err=%v", changed, err)
	}
	st, err := os.Stat(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", st.Mode().Perm())
	}
	if changed, err := WriteConfig(dir, []byte("one")); err != nil || changed {
		t.Errorf("same content: changed=%v err=%v", changed, err)
	}
	if changed, err := WriteConfig(dir, []byte("two")); err != nil || !changed {
		t.Errorf("new content: changed=%v err=%v", changed, err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	if string(b) != "two" {
		t.Errorf("content = %q", b)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("temporary files left behind: %v", entries)
	}
	if _, err := WriteConfig(filepath.Join(dir, "missing"), []byte("x")); err == nil {
		t.Error("write into a missing directory succeeded")
	}
}
