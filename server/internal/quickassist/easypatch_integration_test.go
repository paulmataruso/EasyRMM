//go:build integration

package quickassist_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
	"github.com/paulmataruso/easyrmm/server/internal/quickassist"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// withPatching links Acme to the patching engine's stand-in and gives the
// session service the real EasyPatch service (ADR-0080 QA6).
func (f *fx) withPatching() (*eptest.Server, uuid.UUID) {
	f.t.Helper()
	key := bytes.Repeat([]byte{7}, 32)
	ep := eptest.NewEngine(f.t, key)
	signer, err := easypatch.NewSigner(key)
	if err != nil {
		f.t.Fatal(err)
	}
	cl, err := easypatch.NewEngineClient(ep.URL(), signer, "1.0.0")
	if err != nil {
		f.t.Fatal(err)
	}
	svc := easypatch.New(f.db, audit.New(f.db, nil), "1.0.0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := svc.UseEngine(cl); err != nil {
		f.t.Fatal(err)
	}
	org := ep.Org("Acme Patch")
	f.exec(`INSERT INTO easypatch_organizations (organization_id, easypatch_id, easypatch_name) VALUES ($1, $2, 'Acme Patch')`, f.acme, org)
	f.svc.SetPatchIssuer(svc)
	return ep, org
}

// session makes an accepted session of an elevated (or not) runner.
func (f *fx) activeSession(elevated bool) (device uuid.UUID, session uuid.UUID) {
	f.t.Helper()
	tech := f.user(rbac.RoleTechnician, f.acme)
	l := f.oneTime(tech, f.acme)
	tr, _, err := f.svc.Download(f.ctx, f.ip(), l.Token)
	if err != nil {
		f.t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	res, err := f.svc.Enroll(f.ctx, f.ip(), quickassist.EnrollRequest{
		Ticket: base64.StdEncoding.EncodeToString(tr), PublicKey: base64.StdEncoding.EncodeToString(pub), Code: "123456", Consent: true,
		Facts: quickassist.Facts{Hostname: "pc-1", Platform: "windows", OS: "Windows", Version: "1.0", Arch: "amd64", Elevated: elevated},
	})
	if err != nil {
		f.t.Fatal(err)
	}
	sid := uuid.MustParse(res.SessionID)
	if _, err := f.svc.Accept(f.ctx, tech, sid, "123456"); err != nil {
		f.t.Fatal(err)
	}
	return uuid.MustParse(res.DeviceID), sid
}

func TestEasyPatchTokenIsIssuedOnceAndRemovedAtTheEnd(t *testing.T) {
	f := newFx(t)
	ep, epOrg := f.withPatching()
	dev, sid := f.activeSession(true)

	// Before acceptance there is nothing to give; after it, the token comes
	// in one answer only.
	st, err := f.svc.Status(f.ctx, dev)
	if err != nil || st.State != quickassist.SessionActive || st.EasyPatchToken == "" || st.EasyPatchServer == "" {
		t.Fatalf("status after accept: %+v %v", st, err)
	}
	again, _ := f.svc.Status(f.ctx, dev)
	if again.EasyPatchToken != "" {
		t.Fatal("the token was given twice")
	}
	tokens := ep.Tokens()
	if len(tokens) != 1 || tokens[0].Secret != st.EasyPatchToken || tokens[0].MaxUses != 1 || tokens[0].ExpiresIn != 1 || tokens[0].Org != epOrg || tokens[0].Revoked {
		t.Fatalf("tokens: %+v", tokens)
	}
	if n := f.count(`SELECT count(*) FROM quick_assist_sessions WHERE id = $1 AND easypatch_state = 'issued' AND easypatch_token_id = $2`, sid, tokens[0].ID); n != 1 {
		t.Fatal("the session does not know its token")
	}
	// The secret is not stored.
	if n := f.count(`SELECT count(*) FROM quick_assist_sessions s WHERE s::text LIKE '%' || $1 || '%'`, st.EasyPatchToken); n != 0 {
		t.Fatal("the token is in the session row")
	}

	// The agent enrolled in the token's site as the runner's computer.
	site := *tokens[0].Site
	mine := ep.AddEndpoint(epOrg, "pc-1", "", "QA-1")
	ep.Set(func() { mine.Site, mine.SiteName = &site, "Quick Assist" })

	rep := &quickassist.Cleanup{Result: "verified", ManifestSHA256: "ab"}
	if err := f.svc.RunnerEnd(f.ctx, dev, f.ip(), "user", rep); err != nil {
		t.Fatal(err)
	}
	// The removal runs after the report is answered.
	var gone bool
	for range 100 {
		tokRevoked := ep.Tokens()[0].Revoked
		ep.Set(func() { gone = mine.Revoked && tokRevoked })
		if gone {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !gone {
		t.Fatal("the endpoint and the token were not revoked at the end")
	}
	if n := f.count(`SELECT count(*) FROM quick_assist_sessions WHERE id = $1 AND easypatch_state = 'removed'`, sid); n != 1 {
		t.Fatal("the removal is not recorded")
	}
}

func TestEasyPatchTokenOnlyForAnElevatedSessionOfALinkedOrganization(t *testing.T) {
	// Not elevated: inventory only.
	f := newFx(t)
	ep, _ := f.withPatching()
	dev, _ := f.activeSession(false)
	if st, _ := f.svc.Status(f.ctx, dev); st.EasyPatchToken != "" || len(ep.Tokens()) != 0 {
		t.Fatalf("a runner without administrator rights got a token: %+v", st)
	}

	// Not linked: asked once, then never again.
	g := newFx(t)
	g.svc.SetPatchIssuer(mustService(t, g))
	dev, sid := g.activeSession(true)
	if st, _ := g.svc.Status(g.ctx, dev); st.EasyPatchToken != "" {
		t.Fatalf("an unlinked organization got a token: %+v", st)
	}
	if n := g.count(`SELECT count(*) FROM quick_assist_sessions WHERE id = $1 AND easypatch_state = 'unavailable'`, sid); n != 1 {
		t.Fatal("the session asks the engine again at every poll")
	}
}

// mustService is an EasyPatch service with no engine, as before patching is
// set up.
func mustService(t *testing.T, f *fx) *easypatch.Service {
	t.Helper()
	return easypatch.New(f.db, audit.New(f.db, nil), "1.0.0", slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestEasyPatchEndpointIsRevokedForALostSession(t *testing.T) {
	f := newFx(t)
	ep, epOrg := f.withPatching()
	dev, sid := f.activeSession(true)
	st, _ := f.svc.Status(f.ctx, dev)
	if st.EasyPatchToken == "" {
		t.Fatal("no token")
	}
	site := *ep.Tokens()[0].Site
	mine := ep.AddEndpoint(epOrg, "pc-1", "", "QA-1")
	ep.Set(func() { mine.Site, mine.SiteName = &site, "Quick Assist" })

	// The runner went quiet for longer than the session allows.
	f.exec(`UPDATE quick_assist_sessions SET last_seen_at = now() - interval '1 hour' WHERE id = $1`, sid)
	if err := f.svc.Sweep(f.ctx); err != nil {
		t.Fatal(err)
	}
	var gone bool
	for range 100 {
		ep.Set(func() { gone = mine.Revoked })
		if gone {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !gone {
		t.Fatal("the endpoint of a lost session was not revoked")
	}
}
