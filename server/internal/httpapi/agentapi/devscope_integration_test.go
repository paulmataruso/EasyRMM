//go:build integration

package agentapi_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/agents"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/agentapi"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

func buildsOf(t *testing.T, body string) *agents.Builds {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "easyrmm-agent-linux-amd64"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := agents.LoadBuilds(dir)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestDevScopeDownloads has the installers' and agents' downloads of two
// organizations, one in the dev scope and one outside it: only a token or a
// device inside the scope gets the new build; every other download, with an
// outside token, an unknown token, none, or an outside device, gets the
// stable build.
func TestDevScopeDownloads(t *testing.T) {
	inst := testdb.New(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := agents.New(inst.DB, audit.New(inst.DB, time.Now), nil, log)
	fresh, stable := buildsOf(t, "new build"), buildsOf(t, "stable build")
	svc.SetUpdates(fresh, nil)
	svc.SetStable(stable)
	api, err := agentapi.New(svc, fresh, []agentapi.Address{{URL: "https://rmm.example.com"}}, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	var inOrg, outOrg, inSite, outSite uuid.UUID
	if err := inst.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		for _, o := range []struct {
			name      string
			org, site *uuid.UUID
		}{{"Inside", &inOrg, &inSite}, {"Outside", &outOrg, &outSite}} {
			if err := tx.QueryRow(ctx, `INSERT INTO organizations (name) VALUES ($1) RETURNING id`, o.name).Scan(o.org); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, *o.org).Scan(o.site); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sys := access.System("test")
	token := func(site uuid.UUID) string {
		tok, err := svc.CreateToken(ctx, sys, site, agents.TokenInput{Name: "t", ExpiresInDays: 1})
		if err != nil {
			t.Fatal(err)
		}
		return tok.Secret
	}
	inTok, outTok := token(inSite), token(outSite)
	device := func(site uuid.UUID) (string, ed25519.PrivateKey) {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		resp, err := svc.Enroll(ctx, netip.MustParseAddr("192.0.2.10"), agentproto.EnrollRequest{
			Token: token(site), PublicKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
			Facts: agentproto.Facts{Hostname: "h", Platform: "linux", Arch: "amd64", AgentVersion: "1"},
		})
		if err != nil {
			t.Fatal(err)
		}
		return resp.DeviceID, key
	}
	inDev, inKey := device(inSite)
	outDev, outKey := device(outSite)

	newSum, stableSum := fresh.List()[0].SHA256, stable.List()[0].SHA256
	get := func(path string, set func(*http.Request)) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		if set != nil {
			set(req)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	byToken := func(tok string) func(*http.Request) {
		return func(r *http.Request) { r.Header.Set(agentapi.HeaderDeployToken, tok) }
	}
	bySignature := func(dev string, key ed25519.PrivateKey) func(*http.Request) {
		return func(r *http.Request) {
			h, _ := agentproto.Sign(key, dev, http.MethodGet, r.URL.RequestURI(), nil, time.Now())
			r.Header.Set("Authorization", h)
		}
	}
	file := "/api/agent/v1/download/easyrmm-agent-linux-amd64"
	sums := "/api/agent/v1/download/SHA256SUMS"
	check := func(name string, set func(*http.Request), want string) {
		t.Helper()
		code, body := get(sums, set)
		if code != 200 || !strings.HasPrefix(body, want+"  easyrmm-agent-linux-amd64") {
			t.Errorf("%s: SHA256SUMS %d %q, want %s", name, code, body, want)
		}
		code, body = get(file, set)
		wantBody := "stable build"
		if want == newSum {
			wantBody = "new build"
		}
		if code != 200 || body != wantBody {
			t.Errorf("%s: build %d %q, want %q", name, code, body, wantBody)
		}
	}

	// No scope: today's behavior, whatever the token.
	check("no scope, no token", nil, newSum)
	check("no scope, outside token", byToken(outTok), newSum)

	t.Cleanup(devscope.Set(inOrg))
	check("no token", nil, stableSum)
	check("outside token", byToken(outTok), stableSum)
	check("unknown token", byToken("ert_unknown"), stableSum)
	check("outside device", bySignature(outDev, outKey), stableSum)
	check("inside token", byToken(inTok), newSum)
	check("inside device", bySignature(inDev, inKey), newSum)
	// A signature that does not verify gets nothing, not the new build.
	if code, _ := get(file, bySignature(inDev, outKey)); code == 200 {
		t.Error("a download with a bad signature was served")
	}
	// The installers send the token with their downloads.
	for _, name := range []string{"install.sh", "install.ps1"} {
		if _, body := get("/api/agent/v1/"+name, nil); !strings.Contains(body, "X-Easyrmm-Token") {
			t.Errorf("%s does not send its token with its downloads", name)
		}
	}
}
