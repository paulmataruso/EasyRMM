//go:build integration

package quickassist_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/quickassist"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

const server = "https://rmm.example.test"

type fx struct {
	t           *testing.T
	ctx         context.Context
	db          *database.DB
	svc         *quickassist.Service
	acme, globe uuid.UUID
	n           int
}

func newFx(t *testing.T) *fx {
	t.Helper()
	inst := testdb.New(t)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	f := &fx{t: t, ctx: context.Background(), db: inst.DB, svc: quickassist.New(inst.DB, audit.New(inst.DB, nil), key, server)}
	f.acme = f.id(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	f.globe = f.id(`INSERT INTO organizations (name) VALUES ('Globex') RETURNING id`)
	return f
}

func (f *fx) id(sql string, args ...any) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&id) }); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *fx) exec(sql string, args ...any) {
	f.t.Helper()
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error { _, err := tx.Exec(f.ctx, sql, args...); return err }); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fx) count(sql string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&n) }); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *fx) user(role rbac.Role, org uuid.UUID) access.Caller {
	f.t.Helper()
	f.n++
	email := fmt.Sprintf("u%d@example.test", f.n)
	id := f.id(`INSERT INTO users (email, display_name) VALUES ($1, $1) RETURNING id`, email)
	p, err := rbac.NewPrincipal(id, []rbac.Assignment{{Role: role, OrganizationID: org}})
	if err != nil {
		f.t.Fatal(err)
	}
	return access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: id, Label: email})
}

func (f *fx) ip() netip.Addr {
	f.n++
	return netip.AddrFrom4([4]byte{10, 1, byte(f.n >> 8), byte(f.n)})
}

func (f *fx) actions(prefix string) []string {
	f.t.Helper()
	var out []string
	err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(f.ctx, `SELECT action || ':' || outcome FROM audit_log WHERE action LIKE $1 ORDER BY id`, prefix+"%")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a string
			if err := rows.Scan(&a); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return out
}

func (f *fx) openMode() {
	f.exec(`INSERT INTO settings (key, value) VALUES ('quickassist.link_mode', '"open"')`)
}

func (f *fx) oneTime(c access.Caller, org uuid.UUID) *quickassist.NewLink {
	f.t.Helper()
	l, err := f.svc.CreateLink(f.ctx, c, quickassist.CreateInput{OrganizationID: org, Kind: quickassist.KindOneTime, Name: "Support"})
	if err != nil {
		f.t.Fatal(err)
	}
	return l
}

// runner plays a runner: it downloads and enrolls with the real protocol.
func (f *fx) runner(token, code string) (*quickassist.EnrollResult, error) {
	f.t.Helper()
	tr, _, err := f.svc.Download(f.ctx, f.ip(), token)
	if err != nil {
		f.t.Fatalf("download: %v", err)
	}
	return f.enroll(tr, code)
}

func (f *fx) enroll(trailer []byte, code string) (*quickassist.EnrollResult, error) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	return f.svc.Enroll(f.ctx, f.ip(), quickassist.EnrollRequest{
		Ticket: base64.StdEncoding.EncodeToString(trailer), PublicKey: base64.StdEncoding.EncodeToString(pub), Code: code, Consent: true,
		Facts: quickassist.Facts{Hostname: "pc-1", Platform: "linux", OS: "Test OS", Version: "1.0", Arch: "amd64", Elevated: true},
	})
}

func TestRestrictedModeIsTheDefault(t *testing.T) {
	f := newFx(t)
	tech := f.user(rbac.RoleTechnician, f.acme)
	admin := f.user(rbac.RoleOrgAdmin, f.acme)

	l := f.oneTime(tech, f.acme)
	if !l.Link.Test || !strings.HasPrefix(l.Token, quickassist.PrefixOneTime) || l.Link.ExpiresAt == nil {
		t.Fatalf("link: %+v", l.Link)
	}
	if _, err := f.svc.CreateLink(f.ctx, admin, quickassist.CreateInput{OrganizationID: f.acme, Kind: quickassist.KindPermanent}); !conflict(err) {
		t.Fatalf("permanent link in the restricted mode: %v", err)
	}
	// One setting lifts it.
	f.openMode()
	if _, err := f.svc.CreateLink(f.ctx, admin, quickassist.CreateInput{OrganizationID: f.acme, Kind: quickassist.KindPermanent, Name: "Help desk"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.CreateLink(f.ctx, tech, quickassist.CreateInput{OrganizationID: f.acme, Kind: quickassist.KindPermanent}); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("a technician made a permanent link: %v", err)
	}
	open := f.oneTime(tech, f.acme)
	if open.Link.Test {
		t.Fatal("open-mode link is marked as a test link")
	}
	// The setting needs the platform-wide permission.
	if err := f.svc.SetMode(f.ctx, admin, quickassist.ModeOwnTest); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("org admin changed the mode: %v", err)
	}
	if err := f.svc.SetMode(f.ctx, access.System("test"), quickassist.ModeOwnTest); err != nil {
		t.Fatal(err)
	}
	if m, _ := f.svc.Mode(f.ctx); m != quickassist.ModeOwnTest {
		t.Fatalf("mode %q", m)
	}
}

func TestOneTimeLinkLifecycleAndNoOracle(t *testing.T) {
	f := newFx(t)
	tech := f.user(rbac.RoleTechnician, f.acme)
	l := f.oneTime(tech, f.acme)

	if p, err := f.svc.Resolve(f.ctx, f.ip(), l.Token); err != nil || p.Organization != "Acme" || p.Server != server {
		t.Fatalf("page: %+v %v", p, err)
	}
	if _, _, err := f.svc.Download(f.ctx, f.ip(), l.Token); err != nil {
		t.Fatal(err)
	}
	// Used, expired, revoked, never existed, wrong prefix: one answer.
	expired := f.oneTime(tech, f.acme)
	f.exec(`UPDATE quick_assist_links SET expires_at = now() - interval '1 second', created_at = now() - interval '2 days' WHERE id = $1`, expired.Link.ID)
	revoked := f.oneTime(tech, f.acme)
	if _, err := f.svc.RevokeLink(f.ctx, tech, revoked.Link.ID, nil); err != nil {
		t.Fatal(err)
	}
	for name, tok := range map[string]string{"used": l.Token, "expired": expired.Token, "revoked": revoked.Token, "unknown": "qal_" + strings.Repeat("A", 43), "junk": "x", "empty": ""} {
		if _, err := f.svc.Resolve(f.ctx, f.ip(), tok); !errors.Is(err, quickassist.ErrLinkUnavailable) {
			t.Errorf("%s resolve: %v", name, err)
		}
		if _, _, err := f.svc.Download(f.ctx, f.ip(), tok); !errors.Is(err, quickassist.ErrLinkUnavailable) {
			t.Errorf("%s download: %v", name, err)
		}
	}
	// The database refuses a one-time link that lives longer than 7 days.
	err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `INSERT INTO quick_assist_links (organization_id, kind, token_hash, expires_at) VALUES ($1, 'one_time', 'x', now() + interval '8 days')`, f.acme)
		return err
	})
	if err == nil {
		t.Fatal("an 8-day one-time link was stored")
	}
	if got := f.actions("quickassist.link."); len(got) < 3 {
		t.Fatalf("audit: %v", got)
	}
}

func TestPermanentLinkLimits(t *testing.T) {
	f := newFx(t)
	f.openMode()
	admin := f.user(rbac.RoleOrgAdmin, f.acme)
	var first *quickassist.NewLink
	for i := range quickassist.MaxPermanentLinks {
		l, err := f.svc.CreateLink(f.ctx, admin, quickassist.CreateInput{OrganizationID: f.acme, Kind: quickassist.KindPermanent, Name: fmt.Sprint(i)})
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = l
		}
	}
	if _, err := f.svc.CreateLink(f.ctx, admin, quickassist.CreateInput{OrganizationID: f.acme, Kind: quickassist.KindPermanent}); !conflict(err) {
		t.Fatalf("sixth permanent link: %v", err)
	}
	// The bucket: a burst of 5, then throttled, whatever the address.
	for i := range 5 {
		if _, _, err := f.svc.Download(f.ctx, f.ip(), first.Token); err != nil {
			t.Fatalf("download %d: %v", i, err)
		}
	}
	if _, _, err := f.svc.Download(f.ctx, f.ip(), first.Token); !errors.Is(err, quickassist.ErrThrottled) {
		t.Fatalf("sixth download: %v", err)
	}
	if got := f.actions(quickassist.ActionLinkThrottled); len(got) != 1 || got[0] != "quickassist.link.throttled:denied" {
		t.Fatalf("throttle audit (kept, not rolled back): %v", got)
	}
	// Paused: the page says so; resumed by anyone with the permission.
	if _, err := f.svc.PauseLink(f.ctx, admin, first.Link.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Resolve(f.ctx, f.ip(), first.Token); !errors.Is(err, quickassist.ErrLinkUnavailable) {
		t.Fatalf("paused: %v", err)
	}
	// Per-address limit: one machine hammering stops.
	ip := f.ip()
	var limited bool
	for range 10 {
		if _, _, err := f.svc.Download(f.ctx, ip, "qap_"+strings.Repeat("B", 43)); errors.Is(err, quickassist.ErrRateLimited) {
			limited = true
		}
	}
	if !limited {
		t.Fatal("no per-address limit")
	}
	// Another organization's administrator cannot see or revoke it.
	other := f.user(rbac.RoleOrgAdmin, f.globe)
	if _, err := f.svc.RevokeLink(f.ctx, other, first.Link.ID, nil); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("cross-organization revoke: %v", err)
	}
	// Revoking somebody else's link needs step-up when the caller supplies one.
	denied := errors.New("step up")
	if _, err := f.svc.RevokeLink(f.ctx, f.user(rbac.RoleOrgAdmin, f.acme), first.Link.ID, func() error { return denied }); !errors.Is(err, denied) {
		t.Fatalf("revoke without step-up: %v", err)
	}
	if _, err := f.svc.RevokeLink(f.ctx, admin, first.Link.ID, func() error { return denied }); err != nil {
		t.Fatalf("revoking one's own link needs no step-up: %v", err)
	}
}

func TestSessionFlow(t *testing.T) {
	f := newFx(t)
	tech := f.user(rbac.RoleTechnician, f.acme)
	l := f.oneTime(tech, f.acme)
	res, err := f.runner(l.Token, "123456")
	if err != nil {
		t.Fatal(err)
	}
	sid := uuid.MustParse(res.SessionID)
	// The device is in the Quick Assist site, flagged, and nothing else made one.
	if n := f.count(`SELECT count(*) FROM devices d JOIN sites s ON s.id = d.site_id WHERE d.quick_assist AND s.kind = 'quick_assist' AND d.id = $1`, res.DeviceID); n != 1 {
		t.Fatalf("device not in the Quick Assist site: %d", n)
	}
	// Listed under requests; the code is not in the list.
	reqs, err := f.svc.ListSessions(f.ctx, tech, f.acme, []string{quickassist.SessionRequested})
	if err != nil || len(reqs) != 1 || !reqs[0].Elevated {
		t.Fatalf("requests: %v %v", reqs, err)
	}
	// Wrong code: counted, then a fresh right one still works until three.
	var wc *quickassist.ErrWrongCode
	if _, err := f.svc.Accept(f.ctx, tech, sid, "000000"); !errors.As(err, &wc) || wc.Left != 2 {
		t.Fatalf("wrong code: %v", err)
	}
	// Another technician cannot accept a test link's session.
	if _, err := f.svc.Accept(f.ctx, f.user(rbac.RoleTechnician, f.acme), sid, "123456"); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("other technician accepted a test link: %v", err)
	}
	if got := f.actions(quickassist.ActionAccept); len(got) != 1 || got[0] != "quickassist.session.accept:denied" {
		t.Fatalf("denied accept not audited: %v", got)
	}
	// Read-only people cannot accept.
	if _, err := f.svc.Accept(f.ctx, f.user(rbac.RoleReadOnly, f.acme), sid, "123456"); err == nil {
		t.Fatal("read-only accepted")
	}
	x, err := f.svc.Accept(f.ctx, tech, sid, "123456")
	if err != nil || x.State != quickassist.SessionActive || x.AcceptedBy == nil {
		t.Fatalf("accept: %+v %v", x, err)
	}
	if st, _ := f.svc.Status(f.ctx, uuid.MustParse(res.DeviceID)); st.State != quickassist.SessionActive {
		t.Fatalf("runner status: %+v", st)
	}
	// End by the holder; another technician cannot end it.
	if err := f.svc.End(f.ctx, f.user(rbac.RoleTechnician, f.acme), sid); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("non-holder ended: %v", err)
	}
	if err := f.svc.End(f.ctx, tech, sid); err != nil {
		t.Fatal(err)
	}
	if st, _ := f.svc.Status(f.ctx, uuid.MustParse(res.DeviceID)); st.State != quickassist.SessionEnded || st.EndReason != "technician" {
		t.Fatalf("runner not told: %+v", st)
	}
	// The runner reports its cleanup; the key stops working.
	rep := &quickassist.Cleanup{Result: "verified", ManifestSHA256: "ab"}
	if err := f.svc.RunnerEnd(f.ctx, uuid.MustParse(res.DeviceID), f.ip(), "technician", rep); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM quick_assist_sessions WHERE id = $1 AND cleanup = 'verified'`, sid); n != 1 {
		t.Fatal("cleanup not recorded")
	}
	if n := f.count(`SELECT count(*) FROM devices WHERE id = $1 AND agent_public_key IS NULL`, res.DeviceID); n != 1 {
		t.Fatal("the session's key still works")
	}
	for _, a := range f.actions("quickassist.session.") {
		if strings.Contains(a, "123456") {
			t.Fatal("code in the audit log")
		}
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE details::text LIKE '%123456%' OR details::text LIKE '%qal_%'`); n != 0 {
		t.Fatalf("code or token in %d audit rows", n)
	}
}

func TestThreeWrongCodesCloseTheRequest(t *testing.T) {
	f := newFx(t)
	tech := f.user(rbac.RoleTechnician, f.acme)
	res, err := f.runner(f.oneTime(tech, f.acme).Token, "654321")
	if err != nil {
		t.Fatal(err)
	}
	sid := uuid.MustParse(res.SessionID)
	for range quickassist.MaxCodeFailures {
		_, _ = f.svc.Accept(f.ctx, tech, sid, "111111")
	}
	if _, err := f.svc.Accept(f.ctx, tech, sid, "654321"); !conflict(err) {
		t.Fatalf("right code after three wrong: %v", err)
	}
	if st, _ := f.svc.Status(f.ctx, uuid.MustParse(res.DeviceID)); st.State != quickassist.SessionDeclined || st.EndReason != "code_failed" {
		t.Fatalf("runner: %+v", st)
	}
	if got := f.actions(quickassist.ActionDecline); len(got) != 1 {
		t.Fatalf("audit: %v", got)
	}
}

func TestTicketRefusals(t *testing.T) {
	f := newFx(t)
	tech := f.user(rbac.RoleTechnician, f.acme)
	l := f.oneTime(tech, f.acme)
	tr, _, err := f.svc.Download(f.ctx, f.ip(), l.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.enroll(tr, "12345"); err == nil {
		t.Fatal("a five-digit code")
	}
	if _, err := f.enroll([]byte("junk"), "123456"); !errors.Is(err, quickassist.ErrTicket) {
		t.Fatalf("junk ticket: %v", err)
	}
	if _, err := f.enroll(tr, "123456"); err != nil {
		t.Fatal(err)
	}
	// The one-time link starts one session only.
	if _, err := f.enroll(tr, "123456"); !errors.Is(err, quickassist.ErrTicket) {
		t.Fatalf("second session from a one-time link: %v", err)
	}
	// A ticket another server signed.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	f2 := quickassist.New(f.db, audit.New(f.db, nil), other, server)
	l2 := f.oneTime(tech, f.acme)
	tr2, _, _ := f2.Download(f.ctx, f.ip(), l2.Token)
	if _, err := f.enroll(tr2, "123456"); !errors.Is(err, quickassist.ErrTicket) {
		t.Fatalf("foreign ticket: %v", err)
	}
	// A ticket for a link revoked after its download still does not enroll.
	l3 := f.oneTime(tech, f.acme)
	tr3, _, _ := f.svc.Download(f.ctx, f.ip(), l3.Token)
	f.exec(`UPDATE quick_assist_links SET paused = true WHERE id = $1`, l3.Link.ID)
	if _, err := f.enroll(tr3, "123456"); !errors.Is(err, quickassist.ErrTicket) {
		t.Fatalf("paused link enrolled: %v", err)
	}
}

func TestDevScopeBlocksOtherOrganizations(t *testing.T) {
	f := newFx(t)
	techG := f.user(rbac.RoleTechnician, f.globe)
	techA := f.user(rbac.RoleTechnician, f.acme)
	lg := f.oneTime(techG, f.globe)
	tr, _, err := f.svc.Download(f.ctx, f.ip(), lg.Token)
	if err != nil {
		t.Fatal(err)
	}
	defer devscope.Set(f.acme)()
	if _, err := f.svc.CreateLink(f.ctx, techG, quickassist.CreateInput{OrganizationID: f.globe, Kind: quickassist.KindOneTime}); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("link outside the scope: %v", err)
	}
	if _, err := f.svc.Resolve(f.ctx, f.ip(), lg.Token); !errors.Is(err, quickassist.ErrLinkUnavailable) {
		t.Fatalf("page outside the scope: %v", err)
	}
	if _, _, err := f.svc.Download(f.ctx, f.ip(), lg.Token); !errors.Is(err, quickassist.ErrLinkUnavailable) {
		t.Fatalf("download outside the scope: %v", err)
	}
	if _, err := f.enroll(tr, "123456"); !errors.Is(err, quickassist.ErrTicket) {
		t.Fatalf("enrollment outside the scope: %v", err)
	}
	if f.count(`SELECT count(*) FROM quick_assist_sessions`) != 0 {
		t.Fatal("a session was made outside the scope")
	}
	if _, err := f.svc.CreateLink(f.ctx, techA, quickassist.CreateInput{OrganizationID: f.acme, Kind: quickassist.KindOneTime}); err != nil {
		t.Fatalf("link inside the scope: %v", err)
	}
}

func TestQueueEvictionTakeoverSweepAndRLS(t *testing.T) {
	f := newFx(t)
	f.openMode()
	admin := f.user(rbac.RoleOrgAdmin, f.acme)
	perm, err := f.svc.CreateLink(f.ctx, admin, quickassist.CreateInput{OrganizationID: f.acme, Kind: quickassist.KindPermanent, Name: "Desk"})
	if err != nil {
		t.Fatal(err)
	}
	// Fill the queue; the oldest unanswered request makes room.
	var first *quickassist.EnrollResult
	for i := range quickassist.WaitingCap + 1 {
		f.exec(`UPDATE quick_assist_links SET bucket_tokens = 5 WHERE id = $1`, perm.Link.ID)
		r, err := f.runner(perm.Token, "123456")
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = r
		}
		f.exec(`UPDATE quick_assist_sessions SET requested_at = now() - make_interval(secs => 100 - $2::int) WHERE id = $1`, r.SessionID, i)
	}
	if n := f.count(`SELECT count(*) FROM quick_assist_sessions WHERE state = 'requested'`); n != quickassist.WaitingCap {
		t.Fatalf("waiting: %d", n)
	}
	if st, _ := f.svc.Status(f.ctx, uuid.MustParse(first.DeviceID)); st.State != quickassist.SessionDeclined || st.EndReason != "evicted" {
		t.Fatalf("evicted runner: %+v", st)
	}
	// Accept one (open mode: no test restriction), then take it over.
	var sid uuid.UUID
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT id FROM quick_assist_sessions WHERE state = 'requested' LIMIT 1`).Scan(&sid)
	}); err != nil {
		t.Fatal(err)
	}
	tech := f.user(rbac.RoleTechnician, f.acme)
	if _, err := f.svc.Accept(f.ctx, tech, sid, "123456"); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Takeover(f.ctx, tech, sid); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("technician took over: %v", err)
	}
	if err := f.svc.Takeover(f.ctx, admin, sid); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.End(f.ctx, tech, sid); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("previous holder ended after the takeover: %v", err)
	}
	// Sweep: a quiet runner is lost; an ended session never reported is unconfirmed.
	f.exec(`UPDATE quick_assist_sessions SET last_seen_at = now() - interval '11 minutes' WHERE id = $1`, sid)
	if err := f.svc.Sweep(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM quick_assist_sessions WHERE id = $1 AND state = 'lost' AND cleanup = 'unconfirmed'`, sid); n != 1 {
		t.Fatal("session not marked lost and unconfirmed")
	}
	if n := f.count(`SELECT count(*) FROM quick_assist_sessions WHERE state = 'declined' AND end_reason = 'not_accepted'`); n == 0 {
		// requests were 100 seconds old at most: none expired yet.
		f.exec(`UPDATE quick_assist_sessions SET requested_at = now() - interval '11 minutes', last_seen_at = now() WHERE state = 'requested'`)
		if err := f.svc.Sweep(f.ctx); err != nil {
			t.Fatal(err)
		}
		if f.count(`SELECT count(*) FROM quick_assist_sessions WHERE state = 'requested'`) != 0 {
			t.Fatal("old requests survived the sweep")
		}
	}
	// Retention: old ended sessions and their devices go.
	f.exec(`UPDATE quick_assist_sessions SET ended_at = now() - interval '31 days' WHERE state <> 'requested'`)
	if err := f.svc.Sweep(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.count(`SELECT count(*) FROM quick_assist_sessions WHERE ended_at < now() - interval '30 days'`) != 0 {
		t.Fatal("retention did not delete")
	}
	// A technician of another organization sees nothing.
	if _, err := f.svc.ListSessions(f.ctx, f.user(rbac.RoleTechnician, f.globe), f.acme, []string{quickassist.SessionActive}); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("cross-organization list: %v", err)
	}
}

func conflict(err error) bool {
	e, ok := apperr.As(err)
	return ok && e.Kind == apperr.KindConflict
}

func TestHolderRuleOnRemoteToolsAndFloodNotice(t *testing.T) {
	f := newFx(t)
	f.openMode()
	admin := f.user(rbac.RoleOrgAdmin, f.acme)
	tech := f.user(rbac.RoleTechnician, f.acme)
	other := f.user(rbac.RoleTechnician, f.acme)

	// An ordinary device is not touched by the rule.
	site := f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, f.acme)
	plain := f.id(`INSERT INTO devices (organization_id, site_id, name, hostname) VALUES ($1, $2, 'pc', 'pc') RETURNING id`, f.acme, site)
	if err := quickassist.Guard(f.ctx, f.db, other, plain); err != nil {
		t.Fatalf("ordinary device: %v", err)
	}

	perm, err := f.svc.CreateLink(f.ctx, admin, quickassist.CreateInput{OrganizationID: f.acme, Kind: quickassist.KindPermanent, Name: "Desk"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := f.runner(perm.Token, "123456")
	if err != nil {
		t.Fatal(err)
	}
	dev, sid := uuid.MustParse(res.DeviceID), uuid.MustParse(res.SessionID)
	if err := quickassist.Guard(f.ctx, f.db, tech, dev); !errors.Is(err, quickassist.ErrNotHeld) {
		t.Fatalf("a waiting request is usable: %v", err)
	}
	if _, err := f.svc.Accept(f.ctx, tech, sid, "123456"); err != nil {
		t.Fatal(err)
	}
	if err := quickassist.Guard(f.ctx, f.db, tech, dev); err != nil {
		t.Fatalf("the holder: %v", err)
	}
	if err := quickassist.Guard(f.ctx, f.db, other, dev); !errors.Is(err, quickassist.ErrNotHeld) {
		t.Fatalf("another technician: %v", err)
	}
	if err := quickassist.Guard(f.ctx, f.db, admin, dev); err != nil {
		t.Fatalf("an administrator may take over: %v", err)
	}
	if err := f.svc.End(f.ctx, tech, sid); err != nil {
		t.Fatal(err)
	}
	if err := quickassist.Guard(f.ctx, f.db, tech, dev); !errors.Is(err, quickassist.ErrNotHeld) {
		t.Fatalf("an ended session is usable: %v", err)
	}

	// The flood notice goes out once per link per day.
	var told []string
	f.svc.OnThrottled(func(_ context.Context, org uuid.UUID, link string) { told = append(told, link) })
	f.exec(`UPDATE quick_assist_links SET bucket_tokens = 0, bucket_at = now() WHERE id = $1`, perm.Link.ID)
	for range 3 {
		_, _, err := f.svc.Download(f.ctx, f.ip(), perm.Token)
		if !errors.Is(err, quickassist.ErrThrottled) {
			t.Fatalf("download: %v", err)
		}
	}
	if len(told) != 1 || told[0] != "Desk" {
		t.Fatalf("told %v", told)
	}
}
