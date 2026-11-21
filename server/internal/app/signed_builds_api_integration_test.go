//go:build integration

package app_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/agents"
	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// zeros reads as zero bytes, endlessly.
type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// upload sends data as the request body, as the console's file upload does.
func upload(body io.Reader) func(*http.Request) {
	return func(r *http.Request) {
		r.Body = io.NopCloser(body)
		r.ContentLength = -1
		r.Header.Set("Content-Type", "application/octet-stream")
	}
}

func hexSHA(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// TestSignedAgentBuildsAPI uploads a signed Windows build through the
// console API and has agents download it (ADR-0049). The Windows build is
// the Authenticode reader's test program; see its testdata/README.md.
func TestSignedAgentBuildsAPI(t *testing.T) {
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
	acme := orgID(t, admin, "Acme")
	const file = "easyrmm-agent-windows-amd64.exe"

	// The file to sign.
	r := admin.do("GET", "/api/v1/settings/agent-updates/release/"+file, nil)
	if r.status != http.StatusOK || hexSHA(r.body) != hexSHA(tiny) || r.header.Get("X-Checksum-Sha256") != hexSHA(tiny) {
		t.Fatalf("release download: %d %s", r.status, r.header)
	}
	wantStatus(t, admin.do("GET", "/api/v1/settings/agent-updates/release/VERSION", nil), http.StatusNotFound, "not_found")

	// An unsigned file is refused and says why; a signed one is served.
	r = admin.do("POST", "/api/v1/settings/agent-updates/signed", nil, upload(bytes.NewReader(tiny)))
	var refusal struct {
		Error struct {
			Fields map[string]string `json:"fields"`
		} `json:"error"`
	}
	r.decode(t, &refusal)
	if r.status != http.StatusUnprocessableEntity || refusal.Error.Fields["file"] != "This program has no Authenticode signature." {
		t.Errorf("unsigned: %d %s", r.status, r.body)
	}
	wantStatus(t, admin.do("POST", "/api/v1/settings/agent-updates/signed", nil, upload(io.LimitReader(zeros{}, agents.MaxSignedBuildSize+1))),
		http.StatusRequestEntityTooLarge, "too_large")
	var sb struct {
		ID     string `json:"id"`
		Arch   string `json:"arch"`
		SHA256 string `json:"sha256"`
		Served bool   `json:"served"`
		Signer struct {
			Subject    string `json:"subject"`
			Thumbprint string `json:"thumbprint"`
		} `json:"signer"`
	}
	r = admin.do("POST", "/api/v1/settings/agent-updates/signed", nil, upload(bytes.NewReader(signed)))
	if r.status != http.StatusCreated {
		t.Fatalf("upload: %d %s", r.status, r.body)
	}
	r.decode(t, &sb)
	if sb.Arch != "amd64" || sb.SHA256 != hexSHA(signed) || !sb.Served || sb.Signer.Thumbprint == "" {
		t.Errorf("signed build %+v", sb)
	}
	// Agents download it under the build's name; the checksums list it.
	dl := h.client().do("GET", "/api/agent/v1/download/"+file, nil)
	if dl.status != http.StatusOK || hexSHA(dl.body) != hexSHA(signed) || dl.header.Get("X-Checksum-Sha256") != hexSHA(signed) {
		t.Errorf("agent download: %d", dl.status)
	}
	if sums := h.client().do("GET", "/api/agent/v1/download/SHA256SUMS", nil); !bytes.Contains(sums.body, []byte(hexSHA(signed)+"  "+file)) {
		t.Errorf("checksums %s", sums.body)
	}

	var st struct {
		SignedOnly bool `json:"signedOnly"`
		Release    []struct {
			SHA256 string `json:"sha256"`
		} `json:"release"`
		Builds []struct {
			SHA256 string `json:"sha256"`
		} `json:"builds"`
		Signed   []struct{ ID string } `json:"signed"`
		Withheld []string              `json:"withheld"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/settings/agent-updates", nil, &st)
	if len(st.Release) != 1 || st.Release[0].SHA256 != hexSHA(tiny) || len(st.Builds) != 1 || st.Builds[0].SHA256 != hexSHA(signed) ||
		len(st.Signed) != 1 || st.Signed[0].ID != sb.ID || len(st.Withheld) != 0 {
		t.Errorf("settings %+v", st)
	}

	// Only signed builds: the last one cannot be removed.
	admin.expect(http.StatusOK, "PUT", "/api/v1/settings/agent-updates", map[string]any{"mode": "automatic", "maxConcurrent": 5, "signedOnly": true}, &st)
	if !st.SignedOnly {
		t.Error("only signed builds was not stored")
	}
	wantStatus(t, admin.do("DELETE", "/api/v1/settings/agent-updates/signed/"+sb.ID, nil), http.StatusConflict, "last_signed_build")
	admin.expect(http.StatusOK, "PUT", "/api/v1/settings/agent-updates", map[string]any{"mode": "automatic", "maxConcurrent": 5}, &st)
	admin.expect(http.StatusNoContent, "DELETE", "/api/v1/settings/agent-updates/signed/"+sb.ID, nil, nil)
	if dl := h.client().do("GET", "/api/agent/v1/download/"+file, nil); hexSHA(dl.body) != hexSHA(tiny) {
		t.Error("the release's build is not served again")
	}
	wantStatus(t, admin.do("DELETE", "/api/v1/settings/agent-updates/signed/"+sb.ID, nil), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("DELETE", "/api/v1/settings/agent-updates/signed/nope", nil), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("PUT", "/api/v1/settings/agent-updates", map[string]any{"mode": "automatic", "maxConcurrent": 5, "signedOnly": true}),
		http.StatusConflict, "no_signed_builds")

	// Only Super Administrators.
	invite(t, h, admin, "tess@acme.example", []map[string]any{{"role": "org_admin", "organizationId": acme}})
	other := h.client()
	other.signIn("tess@acme.example", "a long and unusual passphrase", "")
	wantStatus(t, other.do("GET", "/api/v1/settings/agent-updates/release/"+file, nil), http.StatusForbidden, "forbidden")
	wantStatus(t, other.do("POST", "/api/v1/settings/agent-updates/signed", nil, upload(bytes.NewReader(signed))), http.StatusForbidden, "forbidden")
	wantStatus(t, other.do("DELETE", "/api/v1/settings/agent-updates/signed/"+uuid.NewString(), nil), http.StatusForbidden, "forbidden")
	wantStatus(t, h.client().do("POST", "/api/v1/settings/agent-updates/signed", nil, upload(bytes.NewReader(signed))), http.StatusUnauthorized, "")

	ctx := context.Background()
	for action, want := range map[string]int{"agent_updates.signed_upload": 1, "agent_updates.signed_remove": 1} {
		var n int
		if err := h.db.DB.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = $1`, action).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		if n != want {
			t.Errorf("%s audited %d times, want %d", action, n, want)
		}
	}
}
