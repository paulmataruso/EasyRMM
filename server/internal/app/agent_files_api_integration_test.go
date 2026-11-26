//go:build integration

package app_test

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/config"
)

// TestAgentFilesAPI reads the hash list of everything the server hands out
// (ADR-0070): MD5 and SHA-256 beside each build, a signed build in place of
// the release's once it is accepted, and the gates.
func TestAgentFilesAPI(t *testing.T) {
	read := func(name string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("..", "agents", "authenticode", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	tiny, signed := read("tiny.exe"), read("tiny-rsa.exe")
	builds := t.TempDir()
	for name, content := range map[string][]byte{"easyrmm-agent-windows-amd64.exe": tiny, "VERSION": []byte("v9\n")} {
		if err := os.WriteFile(filepath.Join(builds, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	h := newHarnessWith(t, false, func(c *config.Config) { c.AgentDir = builds })
	admin, _ := setUp(t, h)

	type listing struct {
		Entries []struct {
			Source, Name, Version, MD5, SHA256, Signer string
			Stale                                      bool
		} `json:"entries"`
		CanRefresh bool `json:"canRefresh"`
	}
	wantStatus(t, h.client().do("GET", "/api/v1/settings/agent-files", nil), http.StatusUnauthorized, "")

	var l listing
	admin.expect(http.StatusOK, "POST", "/api/v1/settings/agent-files/refresh", nil, &l)
	if !l.CanRefresh {
		t.Error("a super administrator may refresh")
	}
	find := func(l listing, name string) (sha, md, signer string, ok bool) {
		for _, e := range l.Entries {
			if e.Source == "server" && e.Name == name {
				return e.SHA256, e.MD5, e.Signer, true
			}
		}
		return "", "", "", false
	}
	const file = "easyrmm-agent-windows-amd64.exe"
	sha, md, _, ok := find(l, file)
	if !ok || sha != hexSHA(tiny) || len(md) != 32 {
		t.Fatalf("list = %+v", l)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/settings/agent-files", nil, &l)

	// A signed build is served in place of the release's, and the list
	// follows without a refresh.
	if r := admin.do("POST", "/api/v1/settings/agent-updates/signed", nil, upload(bytes.NewReader(signed))); r.status != http.StatusCreated {
		t.Fatalf("upload: %d %s", r.status, r.body)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		admin.expect(http.StatusOK, "GET", "/api/v1/settings/agent-files", nil, &l)
		sha, _, signer, _ := find(l, file)
		if sha == hexSHA(signed) && signer != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the list never showed the signed build: %+v", l)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
