//go:build integration

package keystore_test

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/keystore"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// ADR-0081 slice 4: rotation. KEK rotation re-wraps every organization key
// under the new version; organization-key rotation re-seals the records to a
// new key inside the keystore; a key that was read is replaced by a new one
// that is escrowed and verified before the old one is removed.

func (r *reader) newKEK() {
	r.t.Helper()
	_, bf, err := r.ks.NewVersion()
	if err != nil {
		r.t.Fatal(err)
	}
	// A version made but not proved wraps nothing.
	r.svc.RefreshStatus(r.ctx)
	if n, err := r.svc.RewrapKEK(r.ctx); err != nil || n != 0 {
		r.t.Fatalf("a pending KEK version took keys: %d %v", n, err)
	}
	if _, err := r.ks.VerifyRecovery(bf, append([]byte{}, r.code...)); err != nil {
		r.t.Fatal(err)
	}
	r.svc.RefreshStatus(r.ctx)
}

func TestKEKRotationRewrapsEveryKeyAndKeepsTheOldVersion(t *testing.T) {
	r := readFx(t)
	// A second organization has a key too.
	other := r.dv(r.device(r.globex, r.gh, "gx1", "windows"), r.globex, r.gh)
	r.instruction(other)
	if n := r.str(`SELECT count(*)::text FROM keystore_org_keys WHERE kek_version = 1`); n != "2" {
		t.Fatalf("keys on version 1: %s", n)
	}
	r.newKEK()

	// Out of the development scope an organization's keys are left alone: the
	// re-wrap is an automatic behavior.
	restore := devscope.Set(r.globex)
	n, err := r.svc.RewrapKEK(r.ctx)
	restore()
	if err != nil || n != 1 {
		t.Fatalf("re-wrap inside the scope: %d %v", n, err)
	}
	if got := r.str(`SELECT string_agg(organization_id::text || ':' || kek_version::text, ',' ORDER BY kek_version) FROM keystore_org_keys`); !strings.HasSuffix(got, r.globex.String()+":2") && !strings.Contains(got, r.globex.String()+":2") {
		t.Fatalf("keys: %s", got)
	}
	// Resumable: what is left is what a query finds.
	n, err = r.svc.RewrapKEK(r.ctx)
	if err != nil || n != 1 {
		t.Fatalf("the rest: %d %v", n, err)
	}
	if n, err = r.svc.RewrapKEK(r.ctx); err != nil || n != 0 {
		t.Fatalf("nothing is left, yet %d moved (%v)", n, err)
	}
	if got := r.str(`SELECT count(*)::text FROM keystore_org_keys WHERE wrapped_private LIKE 'ks1.2.%' AND kek_version = 2`); got != "2" {
		t.Fatalf("wrapped under version 2: %s", got)
	}
	if got := r.str(`SELECT count(*)::text FROM audit_log WHERE action = $1`, keystore.ActionRewrapped); got != "2" {
		t.Fatalf("audit rows: %s", got)
	}
	use, err := r.svc.KEKUsage(r.ctx)
	if err != nil || len(use) != 1 || use[0].Version != 2 || use[0].Keys != 2 {
		t.Fatalf("usage: %+v %v", use, err)
	}
	// Nothing was deleted: the keystore still holds version 1.
	st := r.svc.RefreshStatus(r.ctx)
	if len(st.Versions) != 2 || st.Primary != 2 {
		t.Fatalf("versions: %+v", st)
	}
	// A key read after the move works (it opens under version 2), and a record
	// is untouched.
	c, ctx := r.person("reader@example.com", rbac.RoleTechnician, rbac.RoleKeyReader)
	r.step.set(ctx.Value(ctxUser{}).(uuid.UUID), true)
	res, err := r.read(c, ctx, goodReason)
	if err != nil || string(res.Key) != password1 {
		t.Fatalf("read after the re-wrap: %v", err)
	}
	res.Wipe()
}

func TestKEKReconciliationFindsADifferenceBetweenRecordAndKey(t *testing.T) {
	r := readFx(t)
	r.newKEK()
	if _, err := r.svc.RewrapKEK(r.ctx); err != nil {
		t.Fatal(err)
	}
	if n, err := r.svc.ReconcileKEK(r.ctx); err != nil || n != 0 || r.open(keystore.AlertRewrapDrift) != 0 {
		t.Fatalf("reconcile when right: %d %v", n, err)
	}
	r.exec(`UPDATE keystore_org_keys SET kek_version = 1`)
	if n, err := r.svc.ReconcileKEK(r.ctx); err != nil || n != 1 || r.open(keystore.AlertRewrapDrift) != 1 {
		t.Fatalf("reconcile when drifted: %d %v", n, err)
	}
	r.exec(`UPDATE keystore_org_keys SET kek_version = 2`)
	if _, err := r.svc.ReconcileKEK(r.ctx); err != nil || r.open(keystore.AlertRewrapDrift) != 0 {
		t.Fatalf("the alert did not close: %v", err)
	}
}

func TestOrgKeyRotationMovesTheRecordsInsideTheKeystore(t *testing.T) {
	r := readFx(t)
	admin, actx := r.person("admin@example.com", rbac.RoleOrgAdmin)
	tech, tctx := r.person("tech@example.com", rbac.RoleTechnician)
	adminID := actx.Value(ctxUser{}).(uuid.UUID)

	// Permission and step-up come first.
	if err := r.svc.RotateOrgKey(tctx, tech, r.acme); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("a technician rotated the key: %v", err)
	}
	if err := r.svc.RotateOrgKey(actx, admin, r.acme); !errors.Is(err, httpapi.ErrStepUpRequired) {
		t.Fatalf("no step-up: %v", err)
	}
	r.step.set(adminID, true)
	restore := devscope.Set(r.globex)
	err := r.svc.RotateOrgKey(actx, admin, r.acme)
	restore()
	if !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("outside the dev scope: %v", err)
	}
	oldKey := r.str(`SELECT id::text FROM keystore_org_keys WHERE state = 'active'`)
	if err := r.svc.RotateOrgKey(actx, admin, r.acme); err != nil {
		t.Fatal(err)
	}
	if got := r.str(`SELECT string_agg(version::text || ':' || state, ',' ORDER BY version) FROM keystore_org_keys`); got != "1:retired,2:active" {
		t.Fatalf("keys: %s", got)
	}
	// The record moves, whether the background pass or this one does it.
	for range 50 {
		if _, err := r.svc.ResealRecords(r.ctx); err != nil {
			t.Fatal(err)
		}
		if r.str(`SELECT count(*)::text FROM recovery_key_escrows e JOIN keystore_org_keys k ON k.id = e.org_key_id WHERE k.state = 'retired'`) == "0" {
			break
		}
	}
	if got := r.str(`SELECT count(*)::text FROM recovery_key_escrows e JOIN keystore_org_keys k ON k.id = e.org_key_id WHERE k.state = 'active' AND e.state = 'verified'`); got != "1" {
		t.Fatalf("records on the new key: %s", got)
	}
	// The old key is kept, retired and marked drained, never deleted.
	if got := r.str(`SELECT state || ':' || (drained_at IS NOT NULL)::text FROM keystore_org_keys WHERE id = $1`, oldKey); got != "retired:true" {
		t.Fatalf("the old key: %s", got)
	}
	if r.str(`SELECT count(*)::text FROM audit_log WHERE action = $1`, keystore.ActionOrgKeyRotated) != "1" ||
		r.str(`SELECT count(*)::text FROM audit_log WHERE action = $1`, keystore.ActionResealed) != "1" ||
		r.str(`SELECT count(*)::text FROM audit_log WHERE action = $1`, keystore.ActionOrgKeyDrained) != "1" {
		t.Fatal("the rotation is not audited")
	}
	// The moved record reads, and no plaintext was returned by the move itself.
	if n := r.plaintextLogged(); n != 0 {
		t.Fatalf("the move logged %d plaintext-returning entries", n)
	}
	c, ctx := r.person("reader@example.com", rbac.RoleTechnician, rbac.RoleKeyReader)
	r.step.set(ctx.Value(ctxUser{}).(uuid.UUID), true)
	res, err := r.read(c, ctx, goodReason)
	if err != nil || string(res.Key) != password1 {
		t.Fatalf("read after the move: %v", err)
	}
	res.Wipe()
	// Agents get the new key, and a record sealed to the old one is refused.
	key, _ := r.instruction(r.dev)
	if key.KeyVersion != 2 || key.KeyID == oldKey {
		t.Fatalf("instruction: %+v", key)
	}
	oldPayload := key
	oldPayload.KeyID = oldKey
	_, pub := r.instruction(r.dev)
	r.report(r.dev, r.vol, r.prot, "{BBBBBBBB-0000-0000-0000-000000000002}")
	rec := r.record(r.dev, oldPayload, pub, r.vol, "{BBBBBBBB-0000-0000-0000-000000000002}", password2)
	r.later()
	if _, err := r.svc.Upload(r.ctx, r.dev, netip.Addr{}, rec); !errors.Is(err, keystore.ErrKeyOutdated) {
		t.Fatalf("a record sealed to the retired key: %v", err)
	}
	// A KEK rotation after it moves the retired key too: the record of a
	// retired key stays readable until the key is destroyed (slice 5).
	r.newKEK()
	if n, err := r.svc.RewrapKEK(r.ctx); err != nil || n != 2 {
		t.Fatalf("re-wrap of both keys: %d %v", n, err)
	}
}

func TestRotationAfterAReadAddsVerifiesThenRemoves(t *testing.T) {
	r := readFx(t)
	newProt := "{CCCCCCCC-0000-0000-0000-000000000003}"
	verified := func() string {
		return r.str(`SELECT count(*)::text FROM recovery_key_escrows WHERE device_id = $1 AND volume_id = $2 AND state = 'verified'`, r.fx.dev, r.vol)
	}
	// Before a read nothing is due, and the report asks for nothing.
	if a := r.report(r.dev, r.vol, r.prot); len(a.Need) != 0 || a.Watch {
		t.Fatalf("before the read: %+v", a)
	}
	c, ctx := r.person("reader@example.com", rbac.RoleTechnician, rbac.RoleKeyReader)
	r.step.set(ctx.Value(ctxUser{}).(uuid.UUID), true)
	res, err := r.read(c, ctx, goodReason)
	if err != nil {
		t.Fatal(err)
	}
	res.Wipe()
	if got := r.str(`SELECT rotation_due::text FROM recovery_key_escrows WHERE protector_id = $1`, r.prot); got != "true" {
		t.Fatalf("rotation_due = %s", got)
	}
	// The person has ten minutes to type it: no instruction yet, but the agent
	// is told to look again soon.
	if a := r.report(r.dev, r.vol, r.prot); len(a.Need) != 0 || !a.Watch {
		t.Fatalf("inside the ten minutes: %+v", a)
	}
	// An organization outside the dev scope is asked for nothing.
	r.exec(`UPDATE recovery_key_escrows SET rotation_due_at = now() - interval '11 minutes'`)
	restore := devscope.Set(r.globex)
	a := r.report(r.dev, r.vol, r.prot)
	restore()
	if len(a.Need) != 0 {
		t.Fatalf("outside the dev scope: %+v", a)
	}
	// Then: add a new protector, escrow it.
	a = r.report(r.dev, r.vol, r.prot)
	if len(a.Need) != 1 || a.Need[0].Rotating != r.prot || a.Need[0].VolumeID != r.vol {
		t.Fatalf("after ten minutes: %+v", a)
	}
	r.later()
	key, pub := r.instruction(r.dev)
	r.report(r.dev, r.vol, r.prot, newProt)
	ans, err := r.svc.Upload(r.ctx, r.dev, netip.Addr{}, r.record(r.dev, key, pub, r.vol, newProt, password2))
	if err != nil || ans.State != agentproto.EscrowVerified {
		t.Fatalf("the new key: %+v %v", ans, err)
	}
	// Never without a verified key: both are verified now, and the old one
	// still is until the agent removes it.
	if verified() != "2" {
		t.Fatalf("verified records: %s", verified())
	}
	// The server names the old protector for removal, with its successor.
	a = r.report(r.dev, r.vol, r.prot, newProt)
	if len(a.Need) != 1 || len(a.Need[0].Remove) != 1 || a.Need[0].Remove[0] != r.prot || a.Need[0].Successor != newProt {
		t.Fatalf("removal need: %+v", a)
	}
	// Once it is gone, the old record is superseded and the rotation is done.
	a = r.report(r.dev, r.vol, newProt)
	if len(a.Need) != 0 || a.Watch {
		t.Fatalf("after the removal: %+v", a)
	}
	if got := r.state(r.fx.dev, r.prot); got != "superseded" {
		t.Fatalf("old record: %s", got)
	}
	if verified() != "1" || r.state(r.fx.dev, newProt) != "verified" {
		t.Fatalf("the new record is not the verified one")
	}
	if r.str(`SELECT count(*)::text FROM audit_log WHERE action = $1`, keystore.ActionRotated) != "1" {
		t.Fatal("the rotation is not audited")
	}
	// The new key reads and is not due again.
	if r.str(`SELECT rotation_due::text FROM recovery_key_escrows WHERE protector_id = $1`, newProt) != "false" {
		t.Fatal("the new record is due")
	}
}

func TestRotationThatCannotVerifyKeepsTheOldKeyAndAlerts(t *testing.T) {
	r := readFx(t)
	newProt := "{DDDDDDDD-0000-0000-0000-000000000004}"
	c, ctx := r.person("reader@example.com", rbac.RoleTechnician, rbac.RoleKeyReader)
	r.step.set(ctx.Value(ctxUser{}).(uuid.UUID), true)
	res, err := r.read(c, ctx, goodReason)
	if err != nil {
		t.Fatal(err)
	}
	res.Wipe()
	r.later()
	key, pub := r.instruction(r.dev)
	r.report(r.dev, r.vol, r.prot, newProt)
	// A record whose fingerprint is not its password's: the keystore opens it,
	// computes its own and says it does not match.
	bad := r.record(r.dev, key, pub, r.vol, newProt, password2)
	bad.Fingerprint = strings.Repeat("ab", 16)
	ans, err := r.svc.Upload(r.ctx, r.dev, netip.Addr{}, bad)
	if err != nil || ans.State != agentproto.EscrowStale {
		t.Fatalf("the bad record: %+v %v", ans, err)
	}
	if r.open(keystore.AlertRotationUnverified) != 1 {
		t.Fatalf("no alert for a rotation that could not verify: %s", r.str(`SELECT coalesce(string_agg(kind, ','), '') FROM keystore_alerts`))
	}
	// The old key is still the verified one and still due: never left without.
	if r.state(r.fx.dev, r.prot) != "verified" ||
		r.str(`SELECT rotation_due::text FROM recovery_key_escrows WHERE protector_id = $1`, r.prot) != "true" {
		t.Fatal("the old key was touched")
	}
	if r.str(`SELECT count(*)::text FROM audit_log WHERE action = $1 AND outcome = 'failure'`, keystore.ActionRotationFailed) != "1" {
		t.Fatal("the failure is not audited")
	}
	// The alert is the organization's and carries no key.
	if got := r.str(`SELECT detail FROM keystore_alerts WHERE kind = $1`, keystore.AlertRotationUnverified); strings.Contains(got, password1) || strings.Contains(got, password2) {
		t.Fatal("the alert holds a key")
	}
	// The agent then does it right: the alert closes when the rotation is done.
	r.later()
	if ans, err = r.svc.Upload(r.ctx, r.dev, netip.Addr{}, r.record(r.dev, key, pub, r.vol, newProt, password2)); err != nil || ans.State != agentproto.EscrowVerified {
		t.Fatalf("the right record: %+v %v", ans, err)
	}
	r.report(r.dev, r.vol, newProt)
	if r.open(keystore.AlertRotationUnverified) != 0 {
		t.Fatal("the alert stayed open after the rotation was done")
	}
}

func TestRotationLeftUndoneForADayIsAlerted(t *testing.T) {
	r := readFx(t)
	c, ctx := r.person("reader@example.com", rbac.RoleTechnician, rbac.RoleKeyReader)
	r.step.set(ctx.Value(ctxUser{}).(uuid.UUID), true)
	res, err := r.read(c, ctx, goodReason)
	if err != nil {
		t.Fatal(err)
	}
	res.Wipe()
	if err := r.svc.WatchRotations(r.ctx); err != nil || r.open(keystore.AlertRotationUnverified) != 0 {
		t.Fatalf("an alert after a minute: %v", err)
	}
	r.exec(`UPDATE recovery_key_escrows SET rotation_due_at = now() - interval '25 hours'`)
	restore := devscope.Set(r.globex)
	err = r.svc.WatchRotations(r.ctx)
	restore()
	if err != nil || r.open(keystore.AlertRotationUnverified) != 0 {
		t.Fatalf("outside the dev scope: %v", err)
	}
	if err := r.svc.WatchRotations(r.ctx); err != nil || r.open(keystore.AlertRotationUnverified) != 1 {
		t.Fatalf("a day later: %v", err)
	}
	// The mail goes to the administrators once, with no key.
	r.exec(`UPDATE recovery_key_escrows SET rotation_due = false`)
	if err := r.svc.WatchRotations(r.ctx); err != nil || r.open(keystore.AlertRotationUnverified) != 0 {
		t.Fatalf("the alert did not close: %v", err)
	}
}

func TestLUKSRotationUsesTheSlotMachinery(t *testing.T) {
	l := luksFx(t)
	l.report(agentproto.LUKSEscrowable)
	if ans := l.upload(luksTok1, luksPass1, hashA); ans.State != agentproto.EscrowVerified {
		t.Fatalf("upload: %+v", ans)
	}
	slot1 := agentproto.EscrowProtector{ID: luksTok1, Hash: hashA}
	slot2 := agentproto.EscrowProtector{ID: luksTok2, Hash: hashB}
	// A read marks it due (the LUKS read is the BitLocker one's path); here the
	// mark is set directly: the read itself is tested above for both kinds.
	l.exec(`UPDATE recovery_key_escrows SET rotation_due = true, rotation_due_at = now() - interval '11 minutes' WHERE protector_id = $1`, luksTok1)
	need := l.report(agentproto.LUKSEscrowable, slot1).Need
	if len(need) != 1 || len(need[0].Replace) != 1 || need[0].Replace[0] != luksTok1 {
		t.Fatalf("need: %+v", need)
	}
	l.later()
	if ans := l.upload(luksTok2, luksPass2, hashB); ans.State != agentproto.EscrowVerified {
		t.Fatalf("the new slot: %+v", ans)
	}
	// The agent was away before it removed the old slot: the server names it.
	need = l.report(agentproto.LUKSEscrowable, slot1, slot2).Need
	if len(need) != 1 || len(need[0].Remove) != 1 || need[0].Remove[0] != luksTok1 || need[0].Successor != luksTok2 {
		t.Fatalf("removal need: %+v", need)
	}
	// With the old slot gone, the old record is superseded, not stale.
	if need := l.report(agentproto.LUKSEscrowable, slot2).Need; len(need) != 0 {
		t.Fatalf("after removal: %+v", need)
	}
	if got := l.states(luksTok1); got != "superseded" {
		t.Fatalf("old record: %s", got)
	}
	if l.str(`SELECT count(*)::text FROM audit_log WHERE action = $1`, keystore.ActionRotated) != "1" ||
		l.str(`SELECT count(*)::text FROM audit_log WHERE action = $1`, keystore.ActionStale) != "0" {
		t.Fatal("audit")
	}
}
