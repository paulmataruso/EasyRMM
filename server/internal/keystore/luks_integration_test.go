//go:build integration

package keystore_test

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/escrowcrypto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/keystore"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

const (
	luksVolume = "6c4a9e2a-1111-4222-8333-444455556666"
	luksTok1   = "0a0a0a0a-0000-4000-8000-000000000001"
	luksTok2   = "0a0a0a0a-0000-4000-8000-000000000002"
	hashA      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hashB      = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// luksFixture is a Linux device of Acme, its escrow key, and helpers to send
// reports and records the way the agent does.
type luksFixture struct {
	*fx
	dev keystore.Device
	key agentproto.EscrowKeyPayload
	pub []byte
}

func luksFx(t *testing.T) *luksFixture {
	t.Helper()
	f := newFx(t)
	f.exec(`INSERT INTO keystore_org_settings (organization_id, luks_escrow) VALUES ($1, true)`, f.acme)
	id := f.device(f.acme, f.hq, "lx1", "linux")
	dev := f.dv(id, f.acme, f.hq)
	s := f.svc.Instruction(f.ctx, dev, "linux", caps)
	if s == nil {
		t.Fatal("a Linux agent got no escrow key")
	}
	p, pub, err := agentproto.VerifyEscrowKey(f.signPub, *s, id.String(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return &luksFixture{fx: f, dev: dev, key: p, pub: pub}
}

func (l *luksFixture) report(state string, slots ...agentproto.EscrowProtector) agentproto.EscrowVolumesAnswer {
	l.t.Helper()
	out, err := l.svc.ReportVolumes(l.ctx, l.dev, agentproto.EscrowVolumesReport{Kind: agentproto.EscrowLUKS, Volumes: []agentproto.EscrowVolume{
		{ID: luksVolume, Mount: "/", Status: "luks2", State: state, Reason: reasonFor(state), Protectors: slots},
	}})
	if err != nil {
		l.t.Fatal(err)
	}
	return out
}

func reasonFor(state string) string {
	if state == agentproto.LUKSEscrowable {
		return ""
	}
	return "Only a passphrase unlocks this volume."
}

func (l *luksFixture) record(token, pass, hash string) agentproto.EscrowRecord {
	l.t.Helper()
	enc, ct, err := escrowcrypto.Seal(l.pub, escrowcrypto.Context{Org: l.dev.Org.String(), Device: l.dev.ID.String(), Volume: luksVolume, Protector: token, OrgKey: l.key.KeyID}, []byte(pass))
	if err != nil {
		l.t.Fatal(err)
	}
	fp := escrowcrypto.Fingerprint(token, []byte(pass))
	return agentproto.EscrowRecord{VolumeID: luksVolume, ProtectorID: token, Kind: agentproto.EscrowLUKS, KeyID: l.key.KeyID,
		Enc: base64.StdEncoding.EncodeToString(enc), Ciphertext: base64.StdEncoding.EncodeToString(ct),
		Fingerprint: hex.EncodeToString(fp[:]), SlotHash: hash}
}

func (l *luksFixture) upload(token, pass, hash string) agentproto.EscrowAnswer {
	l.t.Helper()
	ans, err := l.svc.Upload(l.ctx, l.dev, netip.Addr{}, l.record(token, pass, hash))
	if err != nil {
		l.t.Fatal(err)
	}
	return ans
}

func (l *luksFixture) states(token string) string {
	return l.state(l.dev.ID, token)
}

const luksPass1 = "abcdefghijklmnopqrstuvwxyzabcdefghijklmn"
const luksPass2 = "zyxwvutsrqponmlkjihgfedcbazyxwvutsrqponm"

func TestLUKSEscrowEndToEnd(t *testing.T) {
	l := luksFx(t)

	// A volume the agent can unlock and that has no key slot of ours needs one.
	need := l.report(agentproto.LUKSEscrowable).Need
	if len(need) != 1 || need[0].VolumeID != luksVolume || need[0].ProtectorID != "" || len(need[0].Replace) != 0 {
		t.Fatalf("need: %+v", need)
	}
	// The key the agent made opens inside the keystore and is verified.
	if ans := l.upload(luksTok1, luksPass1, hashA); ans.State != agentproto.EscrowVerified {
		t.Fatalf("upload: %+v", ans)
	}
	if got := l.str(`SELECT kind || ':' || encode(slot_hash, 'hex') FROM recovery_key_escrows WHERE protector_id = $1`, luksTok1); got != "luks:"+hashA {
		t.Fatalf("stored: %s", got)
	}
	// Once reported with the slot, nothing more is needed, however long it takes.
	l.later()
	if n := l.report(agentproto.LUKSEscrowable, agentproto.EscrowProtector{ID: luksTok1, Hash: hashA}).Need; len(n) != 0 {
		t.Fatalf("a verified volume is asked again: %+v", n)
	}
	st, err := l.svc.DeviceState(l.ctx, access.System("test"), l.dev.ID)
	if err != nil || !st.Applicable || len(st.Volumes) != 1 {
		t.Fatalf("state: %+v %v", st, err)
	}
	v := st.Volumes[0]
	if v.Kind != "luks" || v.State != keystore.StateVerified || len(v.Protectors) != 1 || v.Protectors[0].State != keystore.StateVerified {
		t.Fatalf("volume: %+v", v)
	}

	// A mismatch (an agent bug or a bad copy) is stale and never trusted.
	l.later()
	bad := l.record(luksTok2, luksPass2, hashB)
	other := escrowcrypto.Fingerprint(luksTok2, []byte(luksPass1))
	bad.Fingerprint = hex.EncodeToString(other[:])
	ans, err := l.svc.Upload(l.ctx, l.dev, netip.Addr{}, bad)
	if err != nil || ans.State != agentproto.EscrowStale {
		t.Fatalf("mismatch: %+v %v", ans, err)
	}
	// A BitLocker-shaped secret is not a LUKS passphrase.
	l.later()
	if ans := l.upload(luksTok2, "123456-234567-345678-456789-567890-678901-789012-890123", hashB); ans.State != agentproto.EscrowStale {
		t.Fatalf("a password sent as a passphrase: %+v", ans)
	}
}

func TestLUKSStaleWhenTheSlotGoesOrChanges(t *testing.T) {
	l := luksFx(t)
	l.report(agentproto.LUKSEscrowable)
	l.upload(luksTok1, luksPass1, hashA)
	l.later()

	// The header hash of the slot changed: the key may no longer open it.
	need := l.report(agentproto.LUKSEscrowable, agentproto.EscrowProtector{ID: luksTok1, Hash: hashB}).Need
	if l.states(luksTok1) != "stale" {
		t.Fatalf("a changed slot is %s", l.states(luksTok1))
	}
	// The volume is asked for a new key, naming the stale slot to replace.
	if len(need) != 1 || len(need[0].Replace) != 1 || need[0].Replace[0] != luksTok1 {
		t.Fatalf("need: %+v", need)
	}
	if got := l.str(`SELECT details->>'why' FROM audit_log WHERE action = 'recovery_key.stale' ORDER BY id DESC LIMIT 1`); got != "slot_changed" {
		t.Errorf("audit why = %q", got)
	}
	// The new key verifies; the old slot is replaced by the agent and then gone from the report.
	l.later()
	if ans := l.upload(luksTok2, luksPass2, hashB); ans.State != agentproto.EscrowVerified {
		t.Fatalf("replacement: %+v", ans)
	}
	l.later()
	if n := l.report(agentproto.LUKSEscrowable, agentproto.EscrowProtector{ID: luksTok2, Hash: hashB}).Need; len(n) != 0 {
		t.Fatalf("need after replacement: %+v", n)
	}
	if got := l.states(luksTok1); got != "superseded" {
		t.Fatalf("the replaced slot's record is %s", got)
	}

	// A slot that disappeared (someone removed it): stale at once, and a key is wanted.
	need = l.report(agentproto.LUKSEscrowable).Need
	if l.states(luksTok2) != "stale" || len(need) != 1 {
		t.Fatalf("slot gone: %s %+v", l.states(luksTok2), need)
	}
	if got := l.str(`SELECT details->>'why' FROM audit_log WHERE action = 'recovery_key.stale' ORDER BY id DESC LIMIT 1`); got != "slot_gone" {
		t.Errorf("audit why = %q", got)
	}
}

func TestLUKSCannotEscrowAndManagedElsewhereAreNeverAsked(t *testing.T) {
	l := luksFx(t)
	for _, verdict := range []string{agentproto.LUKSCannotEscrow, agentproto.LUKSManagedElsewhere} {
		if n := l.report(verdict).Need; len(n) != 0 {
			t.Fatalf("%s: %+v", verdict, n)
		}
		st, _ := l.svc.DeviceState(l.ctx, access.System("test"), l.dev.ID)
		if len(st.Volumes) != 1 || st.Volumes[0].State != verdict || st.Volumes[0].Kind != "luks" || st.Volumes[0].Reason == "" {
			t.Fatalf("%s shown as %+v", verdict, st.Volumes)
		}
		// And an upload for it is refused: the volume is not one the agent said it could unlock.
		if _, err := l.svc.Upload(l.ctx, l.dev, netip.Addr{}, l.record(luksTok1, luksPass1, hashA)); !errors.Is(err, keystore.ErrUnknownVolume) {
			t.Fatalf("%s: upload: %v", verdict, err)
		}
		l.later()
	}
	if n := l.str(`SELECT count(*)::text FROM recovery_key_escrows`); n != "0" {
		t.Fatalf("records stored for volumes that cannot be escrowed: %s", n)
	}
}

func TestLUKSReportsOfOneKindNeverDeleteTheOther(t *testing.T) {
	l := luksFx(t)
	l.report(agentproto.LUKSEscrowable)
	// A BitLocker report (an agent of another kind on the same device id, or a bug) forgets no LUKS volume.
	if _, err := l.svc.ReportVolumes(l.ctx, l.dev, agentproto.EscrowVolumesReport{Volumes: nil}); err != nil {
		t.Fatal(err)
	}
	if n := l.str(`SELECT count(*)::text FROM device_encrypted_volumes WHERE kind = 'luks'`); n != "1" {
		t.Fatalf("luks volumes: %s", n)
	}
	// An empty LUKS report forgets it.
	if _, err := l.svc.ReportVolumes(l.ctx, l.dev, agentproto.EscrowVolumesReport{Kind: agentproto.EscrowLUKS}); err != nil {
		t.Fatal(err)
	}
	if n := l.str(`SELECT count(*)::text FROM device_encrypted_volumes`); n != "0" {
		t.Fatalf("volumes after an empty report: %s", n)
	}
	// A report that is not valid is refused.
	if _, err := l.svc.ReportVolumes(l.ctx, l.dev, agentproto.EscrowVolumesReport{Kind: agentproto.EscrowLUKS, Volumes: []agentproto.EscrowVolume{{ID: luksVolume}}}); !errors.Is(err, keystore.ErrRecordMismatch) {
		t.Fatalf("a LUKS volume with no state: %v", err)
	}
}

func TestLUKSOutsideTheDevScopeGetsNothing(t *testing.T) {
	l := luksFx(t)
	defer devscope.Set(l.globex)()
	if s := l.svc.Instruction(l.ctx, l.dev, "linux", caps); s != nil {
		t.Error("an organization outside the dev scope got an escrow key")
	}
	if n := l.report(agentproto.LUKSEscrowable).Need; len(n) != 0 {
		t.Errorf("need outside the dev scope: %+v", n)
	}
	if _, err := l.svc.Upload(l.ctx, l.dev, netip.Addr{}, l.record(luksTok1, luksPass1, hashA)); !errors.Is(err, keystore.ErrOutOfScope) {
		t.Errorf("upload: %v", err)
	}
	if n := l.str(`SELECT count(*)::text FROM device_encrypted_volumes`); n != "0" {
		t.Errorf("volumes stored outside the dev scope: %s", n)
	}
}

// A LUKS passphrase is read through slice 2's path: permission, step-up, reason,
// audit, notice and the keystore's own log. A passphrase typed into the reason is refused.
func TestLUKSReadReturnsThePassphraseThroughTheAuditedPath(t *testing.T) {
	l := luksFx(t)
	r := &reader{fx: l.fx, step: &stepper{ok: map[uuid.UUID]bool{}}, mail: &notifier{}}
	l.svc.SetStepUp(r.step)
	l.svc.SetNotifier(r.mail)
	l.report(agentproto.LUKSEscrowable)
	l.upload(luksTok1, luksPass1, hashA)
	reader, rctx := r.person("reader@example.test", rbac.RoleTechnician, rbac.RoleKeyReader)
	r.step.set(rctx.Value(ctxUser{}).(uuid.UUID), true)
	_, _ = r.person("admin@example.test", rbac.RoleOrgAdmin)

	in := keystore.ReadInput{Volume: luksVolume, Protector: luksTok1, Reason: "Server will not boot after the kernel update"}
	in.Reason = "pasted by mistake: " + luksPass1
	if _, err := l.svc.Read(rctx, reader, l.dev.ID, in); err == nil || !strings.Contains(err.Error(), "validation_failed") {
		t.Fatalf("a passphrase in the reason: %v", err)
	}
	in.Reason = "Server will not boot after the kernel update"
	res, err := l.svc.Read(rctx, reader, l.dev.ID, in)
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Key) != luksPass1 {
		t.Fatal("the key read is not the passphrase that was escrowed")
	}
	res.Wipe()
	for _, b := range res.Key {
		if b != 0 {
			t.Fatal("Wipe left the key")
		}
	}
	if got := r.audits(keystore.ActionRead); !strings.HasSuffix(got, "success:") {
		t.Fatalf("audit: %s", got)
	}
	// The audit row, the notice and the mail say who and why, never the key.
	for _, table := range []string{"audit_log", "keystore_notices"} {
		if n := r.str(`SELECT count(*)::text FROM `+table+` WHERE `+table+`::text LIKE '%' || $1 || '%'`, luksPass1); n != "0" {
			t.Fatalf("the passphrase is in %s", table)
		}
	}
	r.mail.waitFor(t, 1)
	for _, m := range r.mail.text {
		if strings.Contains(m, luksPass1) {
			t.Fatal("the passphrase is in a mail")
		}
	}
	if n := r.plaintextLogged(); n != 1 {
		t.Fatalf("the keystore's log has %d plaintext entries, want 1", n)
	}
	if err := reconcileClean(r); err != nil {
		t.Fatal(err)
	}
}

func reconcileClean(r *reader) error {
	r.svc.SetClock(func() time.Time { return time.Now().Add(keystore.ReconcileGrace + time.Minute) })
	rep, err := r.svc.Reconcile(r.ctx)
	if err != nil {
		return err
	}
	if rep.Reads != 1 || rep.Mismatch != 0 || !rep.ChainOK {
		return errors.New("a read through the console did not reconcile")
	}
	return nil
}

// LUKS escrow is opt-in: with the switch off a volume is reported and shown as
// "escrow off", nothing is asked of the agent and an upload is refused; on, it is asked.
func TestLUKSEscrowIsOptIn(t *testing.T) {
	l := luksFx(t)
	l.exec(`UPDATE keystore_org_settings SET luks_escrow = false`)
	if n := l.report(agentproto.LUKSEscrowable).Need; len(n) != 0 {
		t.Fatalf("need with the switch off: %+v", n)
	}
	st, _ := l.svc.DeviceState(l.ctx, access.System("test"), l.dev.ID)
	if len(st.Volumes) != 1 || st.Volumes[0].State != keystore.StateEscrowOff {
		t.Fatalf("shown as %+v", st.Volumes)
	}
	if _, err := l.svc.Upload(l.ctx, l.dev, netip.Addr{}, l.record(luksTok1, luksPass1, hashA)); !errors.Is(err, keystore.ErrOutOfScope) {
		t.Fatalf("upload with the switch off: %v", err)
	}
	// The switch needs org.manage and step-up, and is audited.
	r := &reader{fx: l.fx, step: &stepper{ok: map[uuid.UUID]bool{}}, mail: &notifier{}}
	l.svc.SetStepUp(r.step)
	tech, tctx := r.person("tech@example.test", rbac.RoleTechnician)
	if _, err := l.svc.SetLUKSEscrow(tctx, tech, l.acme, true); err == nil {
		t.Fatal("a technician turned it on")
	}
	admin, actx := r.person("admin@example.test", rbac.RoleOrgAdmin)
	if _, err := l.svc.SetLUKSEscrow(actx, admin, l.acme, true); !errors.Is(err, httpapi.ErrStepUpRequired) {
		t.Fatalf("without step-up: %v", err)
	}
	r.step.set(actx.Value(ctxUser{}).(uuid.UUID), true)
	set, err := l.svc.SetLUKSEscrow(actx, admin, l.acme, true)
	if err != nil || !set.LUKSEscrow {
		t.Fatalf("turn on: %+v %v", set, err)
	}
	if l.str(`SELECT count(*)::text FROM audit_log WHERE action = 'keystore.luks_escrow'`) != "1" {
		t.Error("not audited")
	}
	l.later()
	if n := l.report(agentproto.LUKSEscrowable).Need; len(n) != 1 {
		t.Fatalf("need with the switch on: %+v", n)
	}
	if ans := l.upload(luksTok1, luksPass1, hashA); ans.State != agentproto.EscrowVerified {
		t.Fatalf("upload: %+v", ans)
	}
}
