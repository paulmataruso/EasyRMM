//go:build integration

package keystore_test

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/keystore"
	"github.com/paulmataruso/easyrmm/server/internal/mailer"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// stepper is the step-up check the console's sessions give: a flag a test
// turns on and off per person, keyed by the user in the context.
type stepper struct {
	mu sync.Mutex
	ok map[uuid.UUID]bool
}

type ctxUser struct{}

func (s *stepper) VerifyStepUp(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, _ := ctx.Value(ctxUser{}).(uuid.UUID)
	if s.ok[id] {
		return nil
	}
	return httpapi.ErrStepUpRequired
}

func (s *stepper) set(id uuid.UUID, on bool) {
	s.mu.Lock()
	s.ok[id] = on
	s.mu.Unlock()
}

// notifier records the mail it is asked to send.
type notifier struct {
	mu   sync.Mutex
	sent []string
	text []string
}

func (n *notifier) Available(context.Context) bool { return true }
func (n *notifier) SendAccountMail(_ context.Context, to string, m mailer.Message, _ mailer.AccountMail) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sent = append(n.sent, to)
	n.text = append(n.text, m.Subject+"\n"+m.Text)
	return nil
}

func (n *notifier) waitFor(t *testing.T, count int) {
	t.Helper()
	for range 100 {
		n.mu.Lock()
		got := len(n.sent)
		n.mu.Unlock()
		if got >= count {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected %d mails, got %d", count, len(n.sent))
}

type reader struct {
	*fx
	step *stepper
	mail *notifier
	dev  keystore.Device
}

// readFx is a keystore with one verified recovery key for a device of Acme.
func readFx(t *testing.T) *reader {
	t.Helper()
	f := newFx(t)
	r := &reader{fx: f, step: &stepper{ok: map[uuid.UUID]bool{}}, mail: &notifier{}}
	f.svc.SetStepUp(r.step)
	f.svc.SetNotifier(r.mail)
	r.dev = f.dv(f.dev, f.acme, f.hq)
	key, pub := f.instruction(r.dev)
	f.report(r.dev, f.vol, f.prot)
	ans, err := f.svc.Upload(f.ctx, r.dev, netip.Addr{}, f.record(r.dev, key, pub, f.vol, f.prot, password1))
	if err != nil || ans.State != agentproto.EscrowVerified {
		t.Fatalf("escrow: %+v %v", ans, err)
	}
	return r
}

// person makes a user with the roles at the organization, and the caller and
// context a request of theirs carries.
func (r *reader) person(email string, roles ...rbac.Role) (access.Caller, context.Context) {
	r.t.Helper()
	id := r.id(`INSERT INTO users (email, display_name) VALUES ($1, $1) RETURNING id`, email)
	var as []rbac.Assignment
	for _, role := range roles {
		a := rbac.Assignment{Role: role}
		if role != rbac.RoleSuperAdmin {
			a.OrganizationID = r.acme
			r.exec(`INSERT INTO role_assignments (user_id, role, organization_id) VALUES ($1, $2, $3)`, id, role, r.acme)
		} else {
			r.exec(`INSERT INTO role_assignments (user_id, role) VALUES ($1, $2)`, id, role)
		}
		as = append(as, a)
	}
	p, err := rbac.NewPrincipal(id, as)
	if err != nil {
		r.t.Fatal(err)
	}
	c := access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: id, Label: email})
	return c, context.WithValue(r.ctx, ctxUser{}, id)
}

func (r *reader) read(c access.Caller, ctx context.Context, reason string) (*keystore.ReadResult, error) {
	return r.svc.Read(ctx, c, r.fx.dev, keystore.ReadInput{Volume: r.vol, Protector: r.prot, Reason: reason, Ticket: "T-1"})
}

func (r *reader) audits(action string) string {
	return r.str(`SELECT coalesce(string_agg(outcome || ':' || coalesce(details->>'code', ''), ',' ORDER BY id), '') FROM audit_log WHERE action = $1`, action)
}

func (r *reader) plaintextLogged() int {
	page, err := (&keystore.Client{Path: r.sock}).Log(r.ctx, 0, 1000)
	if err != nil {
		r.t.Fatal(err)
	}
	n := 0
	for _, e := range page.Entries {
		if e.Plaintext {
			n++
		}
	}
	return n
}

const goodReason = "Laptop will not boot, owner on site (ticket T-1)"

func TestReadNeedsPermissionStepUpAndReason(t *testing.T) {
	r := readFx(t)
	tech, tctx := r.person("tech@example.com", rbac.RoleTechnician)
	su, sctx := r.person("root@example.com", rbac.RoleSuperAdmin)
	reader, rctx := r.person("reader@example.com", rbac.RoleTechnician, rbac.RoleKeyReader)
	r.step.set(rctx.Value(ctxUser{}).(uuid.UUID), true)
	r.step.set(tctx.Value(ctxUser{}).(uuid.UUID), true)
	r.step.set(sctx.Value(ctxUser{}).(uuid.UUID), true)

	// No permission, a technician or even a super administrator: refused and audited.
	for name, who := range map[string]struct {
		c   access.Caller
		ctx context.Context
	}{"technician": {tech, tctx}, "super administrator": {su, sctx}} {
		if res, err := r.read(who.c, who.ctx, goodReason); !errors.Is(err, apperr.ErrForbidden) || res != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if got := r.audits(keystore.ActionRead); got != "denied:no_permission,denied:no_permission" {
		t.Fatalf("audit after refusals: %s", got)
	}

	// Step-up missing.
	r.step.set(rctx.Value(ctxUser{}).(uuid.UUID), false)
	if _, err := r.read(reader, rctx, goodReason); !errors.Is(err, httpapi.ErrStepUpRequired) {
		t.Fatalf("no step-up: %v", err)
	}
	r.step.set(rctx.Value(ctxUser{}).(uuid.UUID), true)

	// No reason, a short one, and a key typed into the reason.
	for name, reason := range map[string]string{"empty": "", "short": "boot fail", "key": "the key is 123456-234567-345678-456789 ok"} {
		if _, err := r.read(reader, rctx, reason); err == nil || !strings.Contains(err.Error(), "validation_failed") {
			t.Fatalf("%s reason: %v", name, err)
		}
	}
	if n := r.plaintextLogged(); n != 0 {
		t.Fatalf("a refused read left %d plaintext-returning entries in the keystore's log", n)
	}
	if got := r.audits(keystore.ActionRead); !strings.HasPrefix(got, "denied:no_permission,denied:no_permission,denied:step_up_required,denied:bad_reason") || strings.Contains(got, "success") {
		t.Fatalf("audit of refusals: %s", got)
	}

	// The read.
	res, err := r.read(reader, rctx, goodReason)
	if err != nil || res.Pending != nil || string(res.Key) != password1 {
		t.Fatalf("read: %v", err)
	}
	res.Wipe()
	for _, b := range res.Key {
		if b != 0 {
			t.Fatal("Wipe left a byte of the key")
		}
	}
	if n := r.plaintextLogged(); n != 1 {
		t.Fatalf("plaintext entries = %d", n)
	}

	// The audit record has the reason and the request ID, never the key, and
	// the keystore's log carries the same ID.
	if r.str(`SELECT details->>'reason' FROM audit_log WHERE action = 'recovery_key.read' AND outcome = 'success'`) != goodReason {
		t.Error("the reason is not in the audit record")
	}
	rid := r.str(`SELECT details->>'requestId' FROM audit_log WHERE action = 'recovery_key.read' AND outcome = 'success'`)
	page, _ := (&keystore.Client{Path: r.sock}).Log(r.ctx, 0, 1000)
	var matched bool
	for _, e := range page.Entries {
		matched = matched || (e.Plaintext && e.RequestID == rid)
	}
	if !matched {
		t.Error("the keystore's log has no entry for the audit record's request ID")
	}

	// The notice: a console row and mail to the super administrator, who
	// gets who, which device and why, never the key.
	r.mail.waitFor(t, 1)
	if r.mail.sent[0] != "root@example.com" || !strings.Contains(r.mail.text[0], "reader@example.com") || !strings.Contains(r.mail.text[0], goodReason) {
		t.Errorf("notice: %v %q", r.mail.sent, r.mail.text)
	}
	if r.str(`SELECT count(*)::text FROM keystore_notices WHERE organization_id = $1`, r.acme) != "1" {
		t.Error("no notice row")
	}

	// Plaintext is nowhere on the server's side: the database, audit, mail.
	var dump strings.Builder
	for _, q := range []string{
		`SELECT coalesce(string_agg(r::text, ' '), '') FROM audit_log r`,
		`SELECT coalesce(string_agg(r::text, ' '), '') FROM keystore_notices r`,
		`SELECT coalesce(string_agg(r::text, ' '), '') FROM recovery_key_requests r`,
		`SELECT coalesce(string_agg(r::text, ' '), '') FROM keystore_alerts r`,
	} {
		dump.WriteString(r.str(q))
	}
	dump.WriteString(strings.Join(r.mail.text, " "))
	for _, p := range []string{password1, strings.ReplaceAll(password1, "-", "")} {
		if strings.Contains(dump.String(), p) {
			t.Fatal("the recovery password is in the audit, a notice or a mail")
		}
	}
	if raw, err := os.ReadFile(filepath.Join(r.dir, "state", "log", "keystore.log")); err != nil || strings.Contains(string(raw), "123456-234567") {
		t.Errorf("the keystore's log: %v", err)
	}
}

func TestReadIsRefusedOutsideTheDevScope(t *testing.T) {
	r := readFx(t)
	c, ctx := r.person("reader@example.com", rbac.RoleTechnician, rbac.RoleKeyReader)
	r.step.set(ctx.Value(ctxUser{}).(uuid.UUID), true)
	defer devscope.Set(r.globex)()
	_, err := r.read(c, ctx, goodReason)
	var ae *apperr.Error
	if !errors.As(err, &ae) || ae.Code != "escrow_off" {
		t.Fatalf("read outside the dev scope: %v", err)
	}
	if n := r.plaintextLogged(); n != 0 {
		t.Fatal("the keystore was asked")
	}
}

func TestReadLimitAtTheServer(t *testing.T) {
	r := readFx(t)
	r.svc.SetReadLimits(keystore.ReadLimits{UserHour: 2, UserDay: 20, OrgHour: 10, OrgDay: 40})
	c, ctx := r.person("reader@example.com", rbac.RoleTechnician, rbac.RoleKeyReader)
	r.step.set(ctx.Value(ctxUser{}).(uuid.UUID), true)
	for i := range 2 {
		res, err := r.read(c, ctx, goodReason)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		res.Wipe()
	}
	_, err := r.read(c, ctx, goodReason)
	var ae *apperr.Error
	if !errors.As(err, &ae) || ae.Kind != apperr.KindTooMany {
		t.Fatalf("over the limit: %v", err)
	}
	if n := r.plaintextLogged(); n != 2 {
		t.Fatalf("the keystore was asked after the server's limit: %d", n)
	}
	if got := r.audits(keystore.ActionRead); !strings.HasSuffix(got, "denied:limit") {
		t.Fatalf("audit: %s", got)
	}
	// Half of the limit and the limit itself raised warnings.
	if r.str(`SELECT count(*)::text FROM keystore_alerts WHERE kind = 'read_limit' AND severity = 'warning'`) == "0" {
		t.Error("no alert for the limit")
	}
}

// A compromised server skips its own limits and the audit; the keystore's hold.
func TestKeystoreLimitHoldsWhenTheServerIsBypassed(t *testing.T) {
	r := readFx(t)
	var wrapped, keyID string
	var enc, ct, fp []byte
	var id uuid.UUID
	if err := r.db.ReadTx(r.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(r.ctx, `SELECT e.id, e.org_key_id::text, k.wrapped_private, e.enc, e.ciphertext, e.fingerprint
			FROM recovery_key_escrows e JOIN keystore_org_keys k ON k.id = e.org_key_id WHERE e.state = 'verified'`).Scan(&id, &keyID, &wrapped, &enc, &ct, &fp)
	}); err != nil {
		t.Fatal(err)
	}
	cl := &keystore.Client{Path: r.sock}
	ec := keystore.EscrowContext{Org: r.acme.String(), Device: r.fx.dev.String(), Volume: r.vol, Protector: r.prot, OrgKey: keyID}
	for i := range keystore.OrgReadsPerHour {
		pt, err := cl.ReadEscrow(r.ctx, uuid.NewString(), id.String(), wrapped, ec, enc, ct, fp)
		if err != nil || string(pt) != password1 {
			t.Fatalf("direct read %d: %v", i, err)
		}
		clear(pt)
	}
	pt, err := cl.ReadEscrow(r.ctx, uuid.NewString(), id.String(), wrapped, ec, enc, ct, fp)
	var re *keystore.RemoteError
	if !errors.As(err, &re) || re.Code != keystore.CodeLimit || pt != nil {
		t.Fatalf("over the keystore's limit: %v %q", err, pt)
	}
}

func TestReconciliationRaisesOnAForgedCall(t *testing.T) {
	r := readFx(t)
	r.person("admin@example.com", rbac.RoleOrgAdmin)
	c, ctx := r.person("reader@example.com", rbac.RoleTechnician, rbac.RoleKeyReader)
	r.step.set(ctx.Value(ctxUser{}).(uuid.UUID), true)
	// One honest read.
	res, err := r.read(c, ctx, goodReason)
	if err != nil {
		t.Fatal(err)
	}
	res.Wipe()
	// One with no audit record: asked of the keystore directly.
	var wrapped, keyID string
	var enc, ct, fp []byte
	var id uuid.UUID
	if err := r.db.ReadTx(r.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(r.ctx, `SELECT e.id, e.org_key_id::text, k.wrapped_private, e.enc, e.ciphertext, e.fingerprint
			FROM recovery_key_escrows e JOIN keystore_org_keys k ON k.id = e.org_key_id WHERE e.state = 'verified'`).Scan(&id, &keyID, &wrapped, &enc, &ct, &fp)
	}); err != nil {
		t.Fatal(err)
	}
	forged := uuid.NewString()
	pt, err := (&keystore.Client{Path: r.sock}).ReadEscrow(r.ctx, forged, id.String(), wrapped,
		keystore.EscrowContext{Org: r.acme.String(), Device: r.fx.dev.String(), Volume: r.vol, Protector: r.prot, OrgKey: keyID}, enc, ct, fp)
	if err != nil {
		t.Fatal(err)
	}
	clear(pt)

	// Inside the grace period nothing is judged yet: the audit record of a
	// read commits just after the keystore answers.
	rep, err := r.svc.Reconcile(r.ctx)
	if err != nil || rep.Mismatch != 0 {
		t.Fatalf("within the grace period: %+v %v", rep, err)
	}
	r.svc.SetClock(func() time.Time { return time.Now().Add(keystore.ReconcileGrace + time.Minute) })
	rep, err = r.svc.Reconcile(r.ctx)
	if err != nil || !rep.ChainOK || rep.Reads != 2 || rep.Mismatch != 1 || len(rep.Unaudited) != 1 || rep.Unaudited[0] != forged {
		t.Fatalf("reconcile: %+v %v", rep, err)
	}
	if got := r.str(`SELECT count(*)::text || ':' || coalesce(min(severity), '') FROM keystore_alerts WHERE kind = 'unaudited_read' AND resolved_at IS NULL`); got != "1:critical" {
		t.Fatalf("alerts = %s", got)
	}
	if r.str(`SELECT count(*)::text FROM audit_log WHERE action = 'keystore.alert'`) != "1" {
		t.Error("the alert is not audited")
	}
	r.mail.waitFor(t, 2) // the read's notice and the critical alert, to the organization's administrator
	// The cursor moved on: the same entries are not judged again.
	if rep, _ := r.svc.Reconcile(r.ctx); rep.Entries != 0 || rep.Mismatch != 0 {
		t.Fatalf("second run: %+v", rep)
	}
}

func TestReconciliationRaisesWhenTheLogIsTamperedWith(t *testing.T) {
	r := readFx(t)
	c, ctx := r.person("reader@example.com", rbac.RoleTechnician, rbac.RoleKeyReader)
	r.step.set(ctx.Value(ctxUser{}).(uuid.UUID), true)
	for range 2 {
		res, err := r.read(c, ctx, goodReason)
		if err != nil {
			t.Fatal(err)
		}
		res.Wipe()
	}
	r.svc.SetClock(func() time.Time { return time.Now().Add(keystore.ReconcileGrace + time.Minute) })
	// Someone with the host edits the log in place while the keystore runs.
	path := filepath.Join(r.dir, "state", "log", "keystore.log")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(raw), `"plaintext":true`, `"plaintext":false`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := r.svc.Reconcile(r.ctx)
	if err != nil || rep.ChainOK {
		t.Fatalf("reconcile: %+v %v", rep, err)
	}
	if r.str(`SELECT count(*)::text FROM keystore_alerts WHERE kind = 'keystore_log_broken' AND severity = 'critical'`) != "1" {
		t.Fatal("no critical alert for a broken log")
	}
}

func TestTwoPersonApproval(t *testing.T) {
	r := readFx(t)
	admin, actx := r.person("admin@example.com", rbac.RoleOrgAdmin)
	reqr, qctx := r.person("req@example.com", rbac.RoleTechnician, rbac.RoleKeyReader)
	apA, aActx := r.person("a@example.com", rbac.RoleTechnician, rbac.RoleKeyApprover)
	apB, bActx := r.person("b@example.com", rbac.RoleTechnician, rbac.RoleKeyApprover, rbac.RoleKeyReader)
	for _, x := range []context.Context{actx, qctx, aActx, bActx} {
		r.step.set(x.Value(ctxUser{}).(uuid.UUID), true)
	}
	// Off by default: a read just works.
	res, err := r.read(reqr, qctx, goodReason)
	if err != nil {
		t.Fatalf("default read: %v", err)
	}
	res.Wipe()

	// It needs two approvers to turn on, and step-up.
	if _, err := r.svc.SetTwoPerson(r.ctx, admin, r.acme, true); err == nil {
		t.Fatal("turned on without a person's context")
	}
	r.exec(`DELETE FROM role_assignments WHERE role = 'key_approver' AND user_id = (SELECT id FROM users WHERE email = 'b@example.com')`)
	if _, err := r.svc.SetTwoPerson(actx, admin, r.acme, true); err == nil || !strings.Contains(err.Error(), "need_approvers") {
		t.Fatalf("one approver: %v", err)
	}
	r.exec(`INSERT INTO role_assignments (user_id, role, organization_id) SELECT id, 'key_approver', $1 FROM users WHERE email = 'b@example.com'`, r.acme)
	r.step.set(actx.Value(ctxUser{}).(uuid.UUID), false)
	if _, err := r.svc.SetTwoPerson(actx, admin, r.acme, true); !errors.Is(err, httpapi.ErrStepUpRequired) {
		t.Fatalf("no step-up: %v", err)
	}
	r.step.set(actx.Value(ctxUser{}).(uuid.UUID), true)
	if s, err := r.svc.SetTwoPerson(actx, admin, r.acme, true); err != nil || !s.TwoPerson || s.Approvers != 2 {
		t.Fatalf("turn on: %+v %v", s, err)
	}

	// The requester waits: nothing is released and the keystore is not asked.
	before := r.plaintextLogged()
	pend, err := r.read(reqr, qctx, goodReason)
	if err != nil || pend.Pending == nil || pend.Key != nil {
		t.Fatalf("two-person read: %+v %v", pend, err)
	}
	if r.plaintextLogged() != before {
		t.Fatal("the keystore was asked before approval")
	}
	reqID := pend.Pending.ID
	// Asking again shows the same request, not a second one.
	again, _ := r.read(reqr, qctx, goodReason)
	if again.Pending == nil || again.Pending.ID != reqID {
		t.Fatal("a second request was made")
	}
	// Reading with the request before it is approved: refused.
	in := keystore.ReadInput{Volume: r.vol, Protector: r.prot, RequestID: reqID}
	if _, err := r.svc.Read(qctx, reqr, r.fx.dev, in); err == nil || !strings.Contains(err.Error(), "approval_pending") {
		t.Fatalf("before approval: %v", err)
	}
	// The requester cannot approve their own, even with the approve permission.
	if _, err := r.svc.Decide(qctx, reqr, reqID, true); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("self approval (no permission): %v", err)
	}
	rb, rbCtx := r.person("rb@example.com", rbac.RoleKeyReader, rbac.RoleKeyApprover, rbac.RoleTechnician)
	r.step.set(rbCtx.Value(ctxUser{}).(uuid.UUID), true)
	own, err := r.svc.Read(rbCtx, rb, r.fx.dev, keystore.ReadInput{Volume: r.vol, Protector: r.prot, Reason: goodReason})
	if err != nil || own.Pending == nil {
		t.Fatalf("own request: %+v %v", own, err)
	}
	if _, err := r.svc.Decide(rbCtx, rb, own.Pending.ID, true); err == nil || !strings.Contains(err.Error(), "own_request") {
		t.Fatalf("a requester approved their own read: %v", err)
	}
	// An approver needs their own step-up.
	r.step.set(aActx.Value(ctxUser{}).(uuid.UUID), false)
	if _, err := r.svc.Decide(aActx, apA, reqID, true); !errors.Is(err, httpapi.ErrStepUpRequired) {
		t.Fatalf("approver without step-up: %v", err)
	}
	r.step.set(aActx.Value(ctxUser{}).(uuid.UUID), true)
	if d, err := r.svc.Decide(aActx, apA, reqID, true); err != nil || d.State != "approved" || d.Approver != "a@example.com" {
		t.Fatalf("approve: %+v %v", d, err)
	}
	// Another reader cannot use the requester's approval.
	if _, err := r.svc.Read(bActx, apB, r.fx.dev, in); err == nil {
		t.Fatal("someone else used the approval")
	}
	// The requester can, once.
	res, err = r.svc.Read(qctx, reqr, r.fx.dev, in)
	if err != nil || string(res.Key) != password1 {
		t.Fatalf("approved read: %v", err)
	}
	res.Wipe()
	if _, err := r.svc.Read(qctx, reqr, r.fx.dev, in); err == nil {
		t.Fatal("an approval was used twice")
	}
	if got := r.str(`SELECT details->>'approver' FROM audit_log WHERE action = 'recovery_key.read' AND outcome = 'success' AND details ? 'approver'`); got != "a@example.com" {
		t.Errorf("the approver is not in the audit record: %q", got)
	}
	// An approval older than ten minutes is no good.
	pend2, _ := r.read(reqr, qctx, goodReason)
	if _, err := r.svc.Decide(bActx, apB, pend2.Pending.ID, true); err != nil {
		t.Fatal(err)
	}
	r.exec(`UPDATE recovery_key_requests SET decided_at = now() - interval '11 minutes' WHERE id = $1`, pend2.Pending.ID)
	if _, err := r.svc.Read(qctx, reqr, r.fx.dev, keystore.ReadInput{Volume: r.vol, Protector: r.prot, RequestID: pend2.Pending.ID}); err == nil || !strings.Contains(err.Error(), "approval_expired") {
		t.Fatalf("an old approval: %v", err)
	}
	// Requests are listed for the requester and the approvers only.
	if rs, _ := r.svc.Requests(aActx, apA); len(rs) == 0 {
		t.Error("an approver sees no requests")
	}
	if rs, _ := r.svc.Requests(actx, admin); len(rs) != 0 {
		t.Error("an administrator without the add-on sees requests")
	}
}

func TestOtherOrganizationsReadersSeeNothing(t *testing.T) {
	r := readFx(t)
	g := r.id(`INSERT INTO users (email, display_name) VALUES ('g@example.com', 'g') RETURNING id`)
	p, _ := rbac.NewPrincipal(g, []rbac.Assignment{{Role: rbac.RoleTechnician, OrganizationID: r.globex}, {Role: rbac.RoleKeyReader, OrganizationID: r.globex}})
	c := access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: g, Label: "g@example.com"})
	ctx := context.WithValue(r.ctx, ctxUser{}, g)
	r.step.set(g, true)
	if _, err := r.read(c, ctx, goodReason); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("another organization's reader: %v", err)
	}
	if ns, err := r.svc.Notices(ctx, c); err != nil || len(ns) != 0 {
		t.Fatalf("notices: %v %v", ns, err)
	}
}

// The server's own limits are lifted here, so that the keystore's are what stops
// the eleventh read; every key that left is accounted for by an audit record, so
// reconciliation raises nothing; and a keystore that is away is refused with the
// reason, audited.
func TestReadStoppedByTheKeystoreAndByItsAbsence(t *testing.T) {
	r := readFx(t)
	r.svc.SetReadLimits(keystore.ReadLimits{UserHour: 100, UserDay: 100, OrgHour: 100, OrgDay: 100})
	c, ctx := r.person("reader@example.com", rbac.RoleTechnician, rbac.RoleKeyReader)
	r.step.set(ctx.Value(ctxUser{}).(uuid.UUID), true)
	for i := range keystore.OrgReadsPerHour {
		res, err := r.read(c, ctx, goodReason)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		res.Wipe()
	}
	_, err := r.read(c, ctx, goodReason)
	var ae *apperr.Error
	if !errors.As(err, &ae) || ae.Code != "keystore_limit" {
		t.Fatalf("over the keystore's limit: %v", err)
	}
	if got := r.str(`SELECT count(*)::text FROM audit_log WHERE action = 'recovery_key.read' AND outcome = 'failure' AND details->>'code' = 'rate_limited' AND details ? 'requestId'`); got != "1" {
		t.Fatalf("failed reads audited with a request ID = %s", got)
	}
	if r.str(`SELECT count(*)::text FROM keystore_alerts WHERE kind = 'read_limit'`) == "0" {
		t.Error("no alert for the keystore's limit")
	}
	r.svc.SetClock(func() time.Time { return time.Now().Add(keystore.ReconcileGrace + time.Minute) })
	if rep, err := r.svc.Reconcile(r.ctx); err != nil || rep.Reads != keystore.OrgReadsPerHour || rep.Mismatch != 0 {
		t.Fatalf("reconcile after honest reads: %+v %v", rep, err)
	}

	r.stopSocket()
	r.svc.RefreshStatus(r.ctx)
	_, err = r.read(c, ctx, goodReason)
	if !errors.As(err, &ae) || ae.Kind != apperr.KindUnavailable {
		t.Fatalf("keystore away: %v", err)
	}
	if got := r.audits(keystore.ActionRead); !strings.HasSuffix(got, "denied:keystore_not_ready") {
		t.Fatalf("audit: %s", got)
	}
	// Notices, alerts and requests list for the people they belong to.
	admin, _ := r.person("admin@example.com", rbac.RoleOrgAdmin)
	if ns, err := r.svc.Notices(r.ctx, admin); err != nil || len(ns) != keystore.OrgReadsPerHour {
		t.Fatalf("notices: %d %v", len(ns), err)
	}
	if as, err := r.svc.Alerts(r.ctx, admin); err != nil || len(as) == 0 {
		t.Fatalf("alerts: %d %v", len(as), err)
	}
	if _, err := r.svc.Notices(r.ctx, access.System("test")); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("a system caller got notices: %v", err)
	}
}
