//go:build integration

package agents

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
)

// waiter is an agent installed with an approval token.
type waiter struct {
	f     *fixture
	token string
	pub   ed25519.PublicKey
	key   ed25519.PrivateKey
	host  string
	ip    netip.Addr
}

func (f *fixture) waiter(token, host string) *waiter {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	return &waiter{f: f, token: token, pub: pub, key: key, host: host, ip: netip.MustParseAddr("198.51.100.20")}
}

func (w *waiter) ask() (*agentproto.EnrollResponse, error) {
	return w.f.svc.Enroll(w.f.ctx, w.ip, agentproto.EnrollRequest{
		Token: w.token, PublicKey: base64.StdEncoding.EncodeToString(w.pub),
		Facts: agentproto.Facts{Hostname: w.host, OS: "Windows 11 Pro", Platform: "windows", Arch: "amd64", AgentVersion: "1.2.0"},
	})
}

func (w *waiter) mustWait() {
	w.f.t.Helper()
	resp, err := w.ask()
	if err != nil {
		w.f.t.Fatal(err)
	}
	if resp.Pending == nil || resp.DeviceID != "" || resp.Pending.Code != agentproto.DeviceCode(w.pub) || resp.Pending.RetrySeconds <= 0 {
		w.f.t.Fatalf("not waiting: %+v %+v", resp, resp.Pending)
	}
}

func (f *fixture) approvalToken(name string, maxUses *int) string {
	f.t.Helper()
	tok, err := f.svc.CreateApprovalToken(f.ctx, f.sys, ApprovalTokenInput{Name: name, ExpiresInDays: 7, MaxUses: maxUses})
	if err != nil {
		f.t.Fatal(err)
	}
	if tok.Token.Status != TokenActive || tok.Token.Name != name {
		f.t.Fatalf("token %+v", tok.Token)
	}
	return tok.Secret
}

func (f *fixture) requests(state string) *RequestList {
	f.t.Helper()
	l, err := f.svc.ListRequests(f.ctx, f.sys, state)
	if err != nil {
		f.t.Fatal(err)
	}
	return l
}

func (f *fixture) requestID(w *waiter) uuid.UUID {
	f.t.Helper()
	return f.uuid(`SELECT id FROM enrollment_requests WHERE public_key = $1`, []byte(w.pub))
}

func TestEnrollmentWithApproval(t *testing.T) {
	f := newFixture(t)
	f.svc.approvalWait = 20 * time.Millisecond
	two := 2
	secret := f.approvalToken("Spring rollout", &two)

	// An enrolled device already has the name the new one reports, as after a reinstall.
	old, _ := f.enroll(f.other, "FRONT-DESK")

	a := f.waiter(secret, "front-desk")
	a.mustWait()
	if f.count(`SELECT count(*) FROM audit_log WHERE action = 'enrollment_request.create' AND actor_type = 'agent' AND details->>'code' = $1`,
		agentproto.DeviceCode(a.pub)) != 1 {
		t.Error("the request is not audited")
	}
	// Asking again keeps one request and refreshes what it shows.
	a.host = "FRONT-DESK-2"
	a.mustWait()
	l := f.requests("pending")
	if len(l.Items) != 1 || l.Waiting != 1 {
		t.Fatalf("pending %+v", l)
	}
	r := l.Items[0]
	if r.Hostname != "FRONT-DESK-2" || r.Code != agentproto.DeviceCode(a.pub) || !r.Online || r.Platform != "windows" ||
		r.OS != "Windows 11 Pro" || r.SourceIP != "198.51.100.20" || r.TokenName != "Spring rollout" {
		t.Errorf("request %+v", r)
	}
	if len(r.Matches) != 0 {
		t.Errorf("matches for another name: %+v", r.Matches)
	}
	a.host = "front-desk"
	a.mustWait()
	if m := f.requests("pending").Items[0].Matches; len(m) != 1 || m[0].DeviceID != old.ID || m[0].SiteName != "Branch" || m[0].OrganizationName != "Acme" {
		t.Errorf("same host name not matched: %+v", m)
	}
	if n, _ := f.svc.Waiting(f.ctx, f.sys); n != 1 {
		t.Errorf("waiting %d", n)
	}
	if f.count(`SELECT uses FROM approval_tokens`) != 1 {
		t.Error("asking again used the token again")
	}

	// A waiting agent learns of its approval at once.
	f.svc.approvalWait = 30 * time.Second
	type answer struct {
		resp *agentproto.EnrollResponse
		err  error
	}
	got := make(chan answer, 1)
	go func() {
		resp, err := a.ask()
		got <- answer{resp, err}
	}()
	time.Sleep(200 * time.Millisecond)
	f.mesh.groups[f.hq] = "mesh//hq"
	group := f.uuid(`INSERT INTO device_groups (organization_id, site_id, name) VALUES ($1, $2, 'Front desk') RETURNING id`, f.org, f.hq)
	d, err := f.svc.Approve(f.ctx, f.sys, ApproveInput{IDs: []uuid.UUID{f.requestID(a)}, SiteID: f.hq, DeviceGroupID: &group})
	if err != nil || len(d.Decided) != 1 || len(d.Devices) != 1 || len(d.Skipped) != 0 {
		t.Fatalf("approve: %+v %v", d, err)
	}
	var ans answer
	select {
	case ans = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting agent did not hear of its approval")
	}
	if ans.err != nil || ans.resp.Pending != nil || ans.resp.DeviceID != d.Devices[0].String() || !ans.resp.MeshAgent.Available ||
		ans.resp.HeartbeatSeconds == 0 {
		t.Fatalf("approved answer %+v %v", ans.resp, ans.err)
	}
	// The device is in the chosen site and group, named after its host, with the agent's key.
	if f.count(`SELECT count(*) FROM devices WHERE id = $1 AND site_id = $2 AND device_group_id = $3 AND name = 'front-desk'
			AND hostname = 'front-desk' AND platform = 'windows' AND agent_public_key = $4 AND enrolled_at IS NOT NULL`,
		d.Devices[0], f.hq, group, []byte(a.pub)) != 1 {
		t.Error("device not created as approved")
	}
	if f.count(`SELECT count(*) FROM audit_log WHERE action = 'enrollment_request.approve' AND device_id = $1 AND site_id = $2
			AND details->>'site' = 'HQ' AND details->>'code' = $3`, d.Devices[0], f.hq, agentproto.DeviceCode(a.pub)) != 1 {
		t.Error("approval not audited")
	}
	// The agent signs in with its own key.
	f.auth(d.Devices[0].String(), a.key)
	// Asking again (a lost answer) gives the same device.
	time.Sleep(2100 * time.Millisecond)
	if resp, err := a.ask(); err != nil || resp.DeviceID != d.Devices[0].String() {
		t.Errorf("asking after approval: %+v %v", resp, err)
	}
	// Once the agent has reported in, the request is forgotten.
	f.exec(`UPDATE devices SET agent_last_seen_at = now() + interval '1 second' WHERE id = $1`, d.Devices[0])
	if err := f.svc.Cleanup(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.count(`SELECT count(*) FROM enrollment_requests WHERE public_key = $1`, []byte(a.pub)) != 0 {
		t.Error("approved request kept after the agent reported in")
	}
	if _, err := a.ask(); !errors.Is(err, ErrKeyInUse) {
		t.Errorf("an enrolled key asking again: %v", err)
	}

	// Rejected: the agent is told so for good.
	f.svc.approvalWait = 20 * time.Millisecond
	b := f.waiter(secret, "kiosk")
	b.mustWait()
	d, err = f.svc.Reject(f.ctx, f.sys, []uuid.UUID{f.requestID(b), uuid.New()})
	if err != nil || len(d.Decided) != 1 || len(d.Skipped) != 1 {
		t.Fatalf("reject: %+v %v", d, err)
	}
	time.Sleep(2100 * time.Millisecond)
	if _, err := b.ask(); !errors.Is(err, ErrRejected) {
		t.Errorf("rejected device asking: %v", err)
	}
	if rl := f.requests("rejected"); len(rl.Items) != 1 || rl.Items[0].DecidedAt == nil || rl.Items[0].Online || rl.Waiting != 0 {
		t.Errorf("rejected %+v", rl)
	}
	if f.count(`SELECT count(*) FROM audit_log WHERE action = 'enrollment_request.reject' AND details->>'device' = 'kiosk'`) != 1 {
		t.Error("rejection not audited")
	}
	// Decided requests cannot be decided again.
	d, err = f.svc.Approve(f.ctx, f.sys, ApproveInput{IDs: []uuid.UUID{f.requestID(b)}, SiteID: f.hq})
	if err != nil || len(d.Decided) != 0 || len(d.Skipped) != 1 {
		t.Errorf("approving a rejected request: %+v %v", d, err)
	}

	// The token allowed two devices.
	c := f.waiter(secret, "third")
	if _, err := c.ask(); !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("used-up token: %v", err)
	}
}

func TestApprovalTokens(t *testing.T) {
	f := newFixture(t)
	f.svc.approvalWait = 10 * time.Millisecond
	secret := f.approvalToken("Branch office", nil)
	d := f.waiter(secret, "pos-01")
	d.mustWait()

	toks, err := f.svc.ListApprovalTokens(f.ctx, f.sys, true)
	if err != nil || len(toks) != 1 || toks[0].Waiting != 1 || toks[0].Uses != 1 || toks[0].MaxUses != nil {
		t.Fatalf("tokens %+v %v", toks, err)
	}
	// Revoked: devices that asked in time still wait, new ones are turned away.
	tok, err := f.svc.RevokeApprovalToken(f.ctx, f.sys, toks[0].ID)
	if err != nil || tok.Status != TokenRevoked {
		t.Fatalf("revoke %+v %v", tok, err)
	}
	if again, err := f.svc.RevokeApprovalToken(f.ctx, f.sys, toks[0].ID); err != nil || !again.RevokedAt.Equal(*tok.RevokedAt) {
		t.Errorf("revoking twice: %v", err)
	}
	time.Sleep(2100 * time.Millisecond)
	d.mustWait()
	if _, err := f.waiter(secret, "pos-02").ask(); !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("new device with a revoked token: %v", err)
	}
	if active, _ := f.svc.ListApprovalTokens(f.ctx, f.sys, true); len(active) != 0 {
		t.Errorf("revoked token listed as active")
	}
	if all, _ := f.svc.ListApprovalTokens(f.ctx, f.sys, false); len(all) != 1 {
		t.Errorf("all tokens: %d", len(all))
	}
	if f.count(`SELECT count(*) FROM audit_log WHERE action IN ('approval_token.create', 'approval_token.revoke')`) != 2 {
		t.Error("token changes not audited")
	}
	if _, err := f.svc.GetApprovalToken(f.ctx, f.sys, uuid.New()); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("unknown token: %v", err)
	}
	if _, err := f.svc.CreateApprovalToken(f.ctx, f.sys, ApprovalTokenInput{Name: " ", ExpiresInDays: 0}); !errors.Is(err, apperr.ErrInvalid) {
		t.Errorf("invalid token input: %v", err)
	}

	// The same key with another approval token is not that device's request.
	other := f.approvalToken("Other", nil)
	if _, err := (&waiter{f: f, token: other, pub: d.pub, key: d.key, host: "pos-01", ip: d.ip}).ask(); !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("same key, other token: %v", err)
	}
	// A key an enrolled device already has cannot ask.
	_, key := f.enroll(f.hq, "server")
	if _, err := (&waiter{f: f, token: other, pub: key.Public().(ed25519.PublicKey), host: "server", ip: d.ip}).ask(); !errors.Is(err, ErrKeyInUse) {
		t.Errorf("enrolled key: %v", err)
	}
}

func TestApprovalValidationAndLimits(t *testing.T) {
	f := newFixture(t)
	f.svc.approvalWait = 10 * time.Millisecond
	secret := f.approvalToken("Rollout", nil)
	w := f.waiter(secret, "lab-01")
	w.mustWait()
	id := f.requestID(w)

	branchGroup := f.uuid(`INSERT INTO device_groups (organization_id, site_id, name) VALUES ($1, $2, 'Tills') RETURNING id`, f.org, f.other)
	many := make([]uuid.UUID, MaxDecide+1)
	for name, in := range map[string]ApproveInput{
		"no devices":         {SiteID: f.hq},
		"too many":           {IDs: many, SiteID: f.hq},
		"no site":            {IDs: []uuid.UUID{id}},
		"unknown site":       {IDs: []uuid.UUID{id}, SiteID: uuid.New()},
		"another site group": {IDs: []uuid.UUID{id}, SiteID: f.hq, DeviceGroupID: &branchGroup},
	} {
		if _, err := f.svc.Approve(f.ctx, f.sys, in); !errors.Is(err, apperr.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := f.svc.Reject(f.ctx, f.sys, nil); !errors.Is(err, apperr.ErrInvalid) {
		t.Errorf("rejecting nothing: %v", err)
	}
	if _, err := f.svc.ListRequests(f.ctx, f.sys, "approved"); !errors.Is(err, apperr.ErrInvalid) {
		t.Errorf("listing an unknown state: %v", err)
	}

	// A waiting agent asking too often is slowed down, per key.
	var limited bool
	for range 10 {
		if _, err := w.ask(); errors.Is(err, ErrRateLimited) {
			limited = true
			break
		}
	}
	if !limited {
		t.Error("a waiting agent is not rate limited")
	}
	f.waiter(secret, "lab-02").mustWait()

	// No more than MaxWaiting wait at once.
	f.exec(`INSERT INTO enrollment_requests (token_id, public_key, hostname, os_description, platform, agent_version, agent_arch)
		SELECT t.id, sha256(i::text::bytea), 'bulk-' || i, '', 'linux', '1', 'amd64'
		FROM approval_tokens t, generate_series(1, $1) i`, MaxWaiting-2)
	if _, err := f.waiter(secret, "one-too-many").ask(); !errors.Is(err, ErrTooManyWaiting) {
		t.Errorf("over the limit: %v", err)
	}
	if l := f.requests("pending"); len(l.Items) != MaxRequests || l.Waiting != MaxWaiting {
		t.Errorf("list of many: %d items, %d waiting", len(l.Items), l.Waiting)
	}

	// Agents that stopped asking, and old rejections, are forgotten.
	f.exec(`UPDATE enrollment_requests SET last_seen_at = now() - interval '8 days' WHERE hostname LIKE 'bulk-%'`)
	if _, err := f.svc.Reject(f.ctx, f.sys, []uuid.UUID{id}); err != nil {
		t.Fatal(err)
	}
	f.exec(`UPDATE enrollment_requests SET decided_at = now() - interval '31 days' WHERE id = $1`, id)
	if err := f.svc.Cleanup(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM enrollment_requests`); n != 1 {
		t.Errorf("%d requests left after cleanup, want lab-02's", n)
	}
}

func TestWaitingEnrollmentsEndWithTheServer(t *testing.T) {
	f := newFixture(t)
	f.svc.approvalWait = time.Minute
	w := f.waiter(f.approvalToken("Rollout", nil), "lab-01")
	done := make(chan error, 1)
	go func() {
		resp, err := w.ask()
		if err == nil && resp.Pending == nil {
			err = errors.New("not pending")
		}
		done <- err
	}()
	time.Sleep(200 * time.Millisecond)
	f.svc.Close()
	f.svc.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a waiting enrollment outlived the server")
	}
}

// TestTokensKeptToShowAgain checks the service's side of ADR-0047: a server
// without a sealer keeps no secrets, and a kept secret is only shown when it
// is the token's own.
func TestTokensKeptToShowAgain(t *testing.T) {
	f := newFixture(t)
	notKept := func(err error) bool {
		e, ok := apperr.As(err)
		return ok && e.Code == "token_not_kept"
	}

	// Without a sealer, a token keeps only its hash.
	plain, err := f.svc.CreateToken(f.ctx, f.sys, f.hq, TokenInput{Name: "unkept", ExpiresInDays: 1})
	if err != nil || plain.Token.Kept {
		t.Fatalf("token without a sealer = %+v, %v", plain, err)
	}
	if _, err := f.svc.RevealToken(f.ctx, f.sys, plain.Token.ID); !notKept(err) {
		t.Errorf("revealing a token without a kept secret: %v", err)
	}
	plainApproval, err := f.svc.CreateApprovalToken(f.ctx, f.sys, ApprovalTokenInput{Name: "unkept", ExpiresInDays: 1})
	if err != nil || plainApproval.Token.Kept {
		t.Fatalf("approval token without a sealer = %+v, %v", plainApproval, err)
	}
	if _, err := f.svc.RevealApprovalToken(f.ctx, f.sys, plainApproval.Token.ID); !notKept(err) {
		t.Errorf("revealing an approval token without a kept secret: %v", err)
	}

	sl, err := secrets.NewSealer(secrets.Key{ID: "k1", Raw: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	f.svc.SetSealer(sl)
	kept, err := f.svc.CreateToken(f.ctx, f.sys, f.hq, TokenInput{Name: "kept", ExpiresInDays: 1})
	if err != nil || !kept.Token.Kept {
		t.Fatalf("token with a sealer = %+v, %v", kept, err)
	}
	shown, err := f.svc.RevealToken(f.ctx, f.sys, kept.Token.ID)
	if err != nil || shown.Secret != kept.Secret {
		t.Fatalf("shown again = %+v, %v", shown, err)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'enrollment_token.reveal' AND target_id = $1`, kept.Token.ID.String()); n != 1 {
		t.Errorf("reveal audit events = %d", n)
	}

	// A secret sealed for the row, but not the token's: refused, not shown.
	other, err := sl.Seal([]byte("ert_not-this-token"), []byte("enrollment_token:"+kept.Token.ID.String()))
	if err != nil {
		t.Fatal(err)
	}
	f.exec(`UPDATE enrollment_tokens SET token_sealed = $2 WHERE id = $1`, kept.Token.ID, other)
	if _, err := f.svc.RevealToken(f.ctx, f.sys, kept.Token.ID); err == nil || !strings.Contains(err.Error(), "does not match its hash") {
		t.Errorf("revealing a secret that is not the token's: %v", err)
	}
	// A token removed between the check and the read.
	if _, err := f.svc.revealSecret(f.ctx, f.sys, deploymentTokens, uuid.New(), TokenActive, audit.Event{}); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("revealing a token that is gone: %v", err)
	}
}
