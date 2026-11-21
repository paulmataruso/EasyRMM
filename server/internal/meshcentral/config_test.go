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
		TrustedProxy: "127.0.0.1", FramingOrigins: []string{"https://rmm.example.com", "https://203.0.113.10"},
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
		"loginCookieEncryptionKey": KeyHex(cfg.LoginKey), "compression": true,
	}
	for k, v := range want {
		if s[k] != v {
			t.Errorf("settings.%s = %v, want %v", k, s[k], v)
		}
	}
	if o, _ := s["allowedFramingOrigins"].([]any); len(o) != 2 || o[0] != "https://rmm.example.com" || o[1] != "https://203.0.113.10" {
		t.Errorf("framing origins = %v", s["allowedFramingOrigins"])
	}
	d := doc.Domains[""]
	if d["newAccounts"] != false || d["guestDeviceSharing"] != false || d["certUrl"] != "https://127.0.0.1:443" || d["lockAgentDownload"] != true {
		t.Errorf("domain = %v", d)
	}
	// The web RDP client for RDP sessions, never with stored credentials;
	// VNC and SSH stay off.
	if d["mstsc"] != true || d["allowSavingDeviceCredentials"] != false || d["novnc"] != false || d["ssh"] != false {
		t.Errorf("remote clients: mstsc %v, saved credentials %v, novnc %v, ssh %v", d["mstsc"], d["allowSavingDeviceCredentials"], d["novnc"], d["ssh"])
	}
	if pr, _ := d["passwordRequirements"].(map[string]any); pr["loginTokens"] != false {
		t.Errorf("user-created login tokens are not disabled: %v", d["passwordRequirements"])
	}
	// The session view tuning, from the web folder where the container
	// mounts the configuration directory.
	if d["webPublicPath"] != "/easyrmm/config/web" {
		t.Errorf("webPublicPath = %v", d["webPublicPath"])
	}
	cfg.ConfigMount = "/srv/mesh-config"
	out, err = cfg.Render()
	if err != nil || !strings.Contains(string(out), `"webPublicPath": "/srv/mesh-config/web"`) {
		t.Errorf("another mount: %v\n%s", err, out)
	}
}

// renderedAllowedOrigin renders cfg and returns the default domain's
// allowedOrigin, failing unless it is a list of strings.
func renderedAllowedOrigin(t *testing.T, cfg ServerConfig) []string {
	t.Helper()
	out, err := cfg.Render()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Settings map[string]json.RawMessage            `json:"settings"`
		Domains  map[string]map[string]json.RawMessage `json:"domains"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	// MeshCentral reads it from the domain only (domains[""].allowedorigin
	// once it lower-cases the keys); `true` would accept any origin.
	for k := range doc.Settings {
		if strings.EqualFold(k, "allowedOrigin") {
			t.Errorf("allowedOrigin in settings")
		}
	}
	var hosts []string
	if err := json.Unmarshal(doc.Domains[""]["allowedOrigin"], &hosts); err != nil {
		t.Fatalf("allowedOrigin = %s: %v", doc.Domains[""]["allowedOrigin"], err)
	}
	return hosts
}

// MeshCentral 1.3.1 compares each entry with the Origin header's host as
// Node's URL.hostname gives it, so entries are written that way; the
// expected values are what Node 24 in MeshCentral's image returns for
// these origins.
func TestRenderAllowedOrigin(t *testing.T) {
	for name, tc := range map[string]struct {
		hostname string
		origins  []string
		want     []string
	}{
		"DNS install with IP access": {
			hostname: "mesh.rmm.example.com",
			origins:  []string{"https://mesh.rmm.example.com", "https://203.0.113.10:4443", "https://[2001:db8::10]:4443"},
			want:     []string{"mesh.rmm.example.com", "203.0.113.10", "[2001:db8::10]"},
		},
		// The public address and the private one behind NAT.
		"IP-only install": {
			hostname: "203.0.113.10",
			origins:  []string{"https://203.0.113.10:4443", "https://192.0.2.10:4443"},
			want:     []string{"203.0.113.10", "192.0.2.10"},
		},
		"IPv6": {
			hostname: "2001:DB8::1",
			origins:  []string{"https://[2001:db8:0:0::1]:4443", "https://[2001:db8::20]:4443", "https://[::ffff:192.0.2.1]:4443"},
			want:     []string{"[2001:db8::1]", "[2001:db8::20]", "[::ffff:c000:201]"},
		},
		"IP access off": {
			hostname: "Mesh.RMM.Example.com",
			origins:  []string{"https://mesh.rmm.example.com"},
			want:     []string{"mesh.rmm.example.com"},
		},
		"no origins given": {
			hostname: "mesh.rmm.example.com",
			want:     []string{"mesh.rmm.example.com"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			cfg.Hostname, cfg.MeshOrigins = tc.hostname, tc.origins
			if got := renderedAllowedOrigin(t, cfg); strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Errorf("allowedOrigin = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestConfigValidation(t *testing.T) {
	for name, mutate := range map[string]func(*ServerConfig){
		"no hostname":     func(c *ServerConfig) { c.Hostname = "" },
		"public listen":   func(c *ServerConfig) { c.Listen = "0.0.0.0:14430" },
		"bad listen":      func(c *ServerConfig) { c.Listen = "localhost" },
		"bad port":        func(c *ServerConfig) { c.Listen = "127.0.0.1:99999" },
		"public port":     func(c *ServerConfig) { c.PublicPort = 0 },
		"proxy not an IP": func(c *ServerConfig) { c.TrustedProxy = "edge" },
		"http origin":     func(c *ServerConfig) { c.FramingOrigins = []string{"http://rmm.example.com"} },
		"origin with path": func(c *ServerConfig) {
			c.FramingOrigins = []string{"https://rmm.example.com", "https://rmm.example.com/app"}
		},
		"no origins":       func(c *ServerConfig) { c.FramingOrigins = nil },
		"http mesh origin": func(c *ServerConfig) { c.MeshOrigins = []string{"http://192.0.2.10:4443"} },
		"mesh origin with path": func(c *ServerConfig) {
			c.MeshOrigins = []string{"https://mesh.rmm.example.com", "https://192.0.2.10:4443/x"}
		},
		"mesh origin without host": func(c *ServerConfig) { c.MeshOrigins = []string{"https://"} },
		"cert URL scheme":          func(c *ServerConfig) { c.CertURL = "ftp://x" },
		"short login key":          func(c *ServerConfig) { c.LoginKey = c.LoginKey[:32] },
		"short session key":        func(c *ServerConfig) { c.SessionKey = "short" },
		"relative mount":           func(c *ServerConfig) { c.ConfigMount = "easyrmm/config" },
		"unclean mount":            func(c *ServerConfig) { c.ConfigMount = "/easyrmm/config/" },
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

func TestWriteWeb(t *testing.T) {
	dir := t.TempDir()
	changed, err := WriteWeb(dir)
	if err != nil || !changed {
		t.Fatalf("first write: changed=%v err=%v", changed, err)
	}
	name := filepath.Join(dir, "web", "scripts", "custom.js")
	b, err := os.ReadFile(name)
	if err != nil || string(b) != string(ViewerScript()) {
		t.Fatalf("custom.js: %v", err)
	}
	if st, _ := os.Stat(name); st.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", st.Mode().Perm())
	}
	// What MeshCentral's pages need from it.
	for _, want := range []string{"ADR-0025", "CreateAgentRemoteDesktop", "createImageBitmap", "connectbutton1"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("custom.js lacks %q", want)
		}
	}
	if changed, err := WriteWeb(dir); err != nil || changed {
		t.Errorf("again: changed=%v err=%v", changed, err)
	}
	if err := os.WriteFile(name, []byte("// edited"), 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := WriteWeb(dir); err != nil || !changed {
		t.Errorf("after an edit: changed=%v err=%v", changed, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteWeb(filepath.Join(dir, "file")); err == nil {
		t.Error("write under a file succeeded")
	}
}
