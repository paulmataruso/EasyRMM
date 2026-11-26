//go:build integration

package keystore_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/escrowcrypto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/keystore"
	"github.com/paulmataruso/easyrmm/server/internal/keystored"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

const (
	password1 = "123456-234567-345678-456789-567890-678901-789012-890123"
	password2 = "111111-222222-333333-444444-555555-666666-777777-888888"
)

type fx struct {
	t         *testing.T
	ctx       context.Context
	db        *database.DB
	svc       *keystore.Service
	ks        *keystored.Keystore
	srv       *keystored.Server
	sock      string
	stop      context.CancelFunc
	done      chan struct{}
	signPub   ed25519.PublicKey
	acme, hq  uuid.UUID
	globex    uuid.UUID
	gh        uuid.UUID
	dev, dev2 uuid.UUID
	vol       string
	prot      string
}

func newFx(t *testing.T) *fx {
	t.Helper()
	inst := testdb.New(t)
	f := &fx{t: t, ctx: context.Background(), db: inst.DB, vol: `\\?\Volume{11111111-1111-1111-1111-111111111111}\`, prot: "{AAAAAAAA-0000-0000-0000-000000000001}"}

	// A real keystore process's code, on a real socket, in file mode (the
	// opt-in stand-in: no TPM and no person needed here).
	dir, err := os.MkdirTemp("", "ks-int")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	f.ks, err = keystored.Open(keystored.Options{Dir: filepath.Join(dir, "state"), Mode: keystore.ModeFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.ks.Close)
	rc, bf, err := f.ks.Init("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.ks.VerifyRecovery(bf, rc); err != nil {
		t.Fatal(err)
	}
	f.sock = filepath.Join(dir, "ks.sock")
	f.startSocket()
	t.Cleanup(f.stopSocket)

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f.signPub = pub
	f.svc = keystore.New(f.db, audit.New(f.db, nil), &keystore.Client{Path: f.sock, Timeout: 10 * time.Second}, priv, slog.New(slog.DiscardHandler))

	f.acme = f.id(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	f.hq = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, f.acme)
	f.globex = f.id(`INSERT INTO organizations (name) VALUES ('Globex') RETURNING id`)
	f.gh = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'Plant') RETURNING id`, f.globex)
	f.dev = f.device(f.acme, f.hq, "pc1", "windows")
	f.dev2 = f.device(f.acme, f.hq, "pc2", "windows")
	return f
}

func (f *fx) startSocket() {
	ln, err := keystored.Listen(f.sock, 0o660)
	if err != nil {
		f.t.Fatal(err)
	}
	uid := uint32(os.Getuid()) //nolint:gosec // a uid
	f.srv = &keystored.Server{KS: f.ks, ServiceUIDs: []uint32{uid}, AdminUID: uid}
	ctx, cancel := context.WithCancel(context.Background())
	f.stop, f.done = cancel, make(chan struct{})
	go func() { _ = f.srv.Serve(ctx, ln, nil); close(f.done) }()
}

func (f *fx) stopSocket() {
	if f.stop != nil {
		f.stop()
		<-f.done
		f.stop = nil
	}
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

func (f *fx) str(sql string, args ...any) string {
	f.t.Helper()
	var s string
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&s) }); err != nil {
		f.t.Fatal(err)
	}
	return s
}

func (f *fx) device(org, site uuid.UUID, name, platform string) uuid.UUID {
	return f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, mesh_node_id) VALUES ($1, $2, $3, $3, $4, $5) RETURNING id`,
		org, site, name, platform, "node//"+name)
}

func (f *fx) dv(id uuid.UUID, org, site uuid.UUID) keystore.Device {
	return keystore.Device{ID: id, Org: org, Site: site, Hostname: "host"}
}

var caps = []string{agentproto.CapEscrow}

// instruction gets the signed key a device's heartbeat would carry and checks
// it the way the agent does.
func (f *fx) instruction(dev keystore.Device) (agentproto.EscrowKeyPayload, []byte) {
	f.t.Helper()
	s := f.svc.Instruction(f.ctx, dev, "windows", caps)
	if s == nil {
		f.t.Fatal("no escrow key instruction")
	}
	p, pub, err := agentproto.VerifyEscrowKey(f.signPub, *s, dev.ID.String(), time.Now())
	if err != nil {
		f.t.Fatal(err)
	}
	return p, pub
}

// record seals a password the way the agent does.
func (f *fx) record(dev keystore.Device, key agentproto.EscrowKeyPayload, pub []byte, volume, protector, password string) agentproto.EscrowRecord {
	f.t.Helper()
	enc, ct, err := escrowcrypto.Seal(pub, escrowcrypto.Context{Org: dev.Org.String(), Device: dev.ID.String(), Volume: volume, Protector: protector, OrgKey: key.KeyID}, []byte(password))
	if err != nil {
		f.t.Fatal(err)
	}
	fp := escrowcrypto.Fingerprint(protector, []byte(password))
	return agentproto.EscrowRecord{VolumeID: volume, ProtectorID: protector, Kind: agentproto.EscrowBitLocker, KeyID: key.KeyID,
		Enc: base64.StdEncoding.EncodeToString(enc), Ciphertext: base64.StdEncoding.EncodeToString(ct), Fingerprint: hex.EncodeToString(fp[:])}
}

func (f *fx) report(dev keystore.Device, volume string, protectors ...string) agentproto.EscrowVolumesAnswer {
	f.t.Helper()
	v := agentproto.EscrowVolume{ID: volume, Mount: "C:", Status: "encrypted"}
	for _, p := range protectors {
		v.Protectors = append(v.Protectors, agentproto.EscrowProtector{ID: p})
	}
	out, err := f.svc.ReportVolumes(f.ctx, dev, agentproto.EscrowVolumesReport{Volumes: []agentproto.EscrowVolume{v}})
	if err != nil {
		f.t.Fatal(err)
	}
	return out
}

// later makes uploads so far older, past the per-volume limit.
func (f *fx) later() {
	f.exec(`UPDATE recovery_key_escrows SET created_at = created_at - interval '10 minutes'`)
}

func (f *fx) state(device uuid.UUID, protector string) string {
	return f.str(`SELECT coalesce(string_agg(state, ','  ORDER BY created_at), '') FROM recovery_key_escrows WHERE device_id = $1 AND protector_id = $2`, device, protector)
}

func TestInstructionConditions(t *testing.T) {
	f := newFx(t)
	dev := f.dv(f.dev, f.acme, f.hq)
	if s := f.svc.Instruction(f.ctx, dev, "linux", caps); s != nil {
		t.Error("a Linux device got an escrow key")
	}
	if s := f.svc.Instruction(f.ctx, dev, "windows", nil); s != nil {
		t.Error("an agent that did not announce the capability got an escrow key")
	}
	p, pub := f.instruction(dev)
	if p.OrgID != f.acme.String() || p.DeviceID != f.dev.String() || p.KeyVersion != 1 || len(pub) != 32 {
		t.Fatalf("payload: %+v", p)
	}
	if n := f.str(`SELECT count(*)::text FROM keystore_org_keys WHERE organization_id = $1 AND state = 'active'`, f.acme); n != "1" {
		t.Fatalf("keys = %s", n)
	}
	// The key is made once, however many heartbeats ask.
	f.instruction(f.dv(f.dev2, f.acme, f.hq))
	if n := f.str(`SELECT count(*)::text FROM keystore_org_keys`); n != "1" {
		t.Fatalf("keys after two devices = %s", n)
	}
	if f.str(`SELECT count(*)::text FROM audit_log WHERE action = 'keystore.org_key_created'`) != "1" {
		t.Error("the key's creation was not audited once")
	}
	// The dev-scope guard: an organization outside it gets no key and no
	// instruction.
	defer devscope.Set(f.globex)()
	if s := f.svc.Instruction(f.ctx, dev, "windows", caps); s != nil {
		t.Error("an organization outside the dev scope got an escrow key")
	}
	gd := f.dv(f.device(f.globex, f.gh, "g1", "windows"), f.globex, f.gh)
	if s := f.svc.Instruction(f.ctx, gd, "windows", caps); s == nil {
		t.Error("the organization in scope got none")
	}
	if _, err := f.svc.Upload(f.ctx, dev, netip.Addr{}, agentproto.EscrowRecord{}); !errors.Is(err, keystore.ErrOutOfScope) {
		t.Errorf("upload outside the dev scope: %v", err)
	}
}

func TestInstructionWaitsForAReadyKeystore(t *testing.T) {
	f := newFx(t)
	f.stopSocket()
	dev := f.dv(f.dev, f.acme, f.hq)
	if s := f.svc.Instruction(f.ctx, dev, "windows", caps); s != nil {
		t.Error("an unreachable keystore gave a key")
	}
	if st := f.svc.RefreshStatus(f.ctx); st.State != keystore.StateUnavailable {
		t.Errorf("status = %s", st.State)
	}
}

func TestEscrowUploadVerifiesInsideTheKeystore(t *testing.T) {
	f := newFx(t)
	dev := f.dv(f.dev, f.acme, f.hq)
	key, pub := f.instruction(dev)

	// A record for a protector that was never reported is refused.
	if _, err := f.svc.Upload(f.ctx, dev, netip.Addr{}, f.record(dev, key, pub, f.vol, f.prot, password1)); !errors.Is(err, keystore.ErrUnknownVolume) {
		t.Fatalf("unreported protector: %v", err)
	}
	need := f.report(dev, f.vol, f.prot)
	if len(need.Need) != 1 || need.Need[0].ProtectorID != f.prot {
		t.Fatalf("need = %+v", need)
	}
	ans, err := f.svc.Upload(f.ctx, dev, netip.MustParseAddr("192.0.2.9"), f.record(dev, key, pub, f.vol, f.prot, password1))
	if err != nil || ans.State != agentproto.EscrowVerified || ans.Again {
		t.Fatalf("upload: %+v %v", ans, err)
	}
	if got := f.state(f.dev, f.prot); got != "verified" {
		t.Fatalf("state = %s", got)
	}
	// Nothing more is needed now.
	if n := f.report(dev, f.vol, f.prot); len(n.Need) != 0 {
		t.Fatalf("need after verified = %+v", n)
	}
	// The same password sent again supersedes, once the limit allows it.
	f.later()
	if ans, err := f.svc.Upload(f.ctx, dev, netip.Addr{}, f.record(dev, key, pub, f.vol, f.prot, password1)); err != nil || ans.State != agentproto.EscrowVerified {
		t.Fatalf("same key again: %+v %v", ans, err)
	}
	if got := f.state(f.dev, f.prot); got != "superseded,verified" {
		t.Fatalf("after same key again: %s", got)
	}

	// The key is in no column and no audit record, in clear.
	var dump strings.Builder
	for _, q := range []string{
		`SELECT coalesce(string_agg(r::text, ' '), '') FROM recovery_key_escrows r`,
		`SELECT coalesce(string_agg(r::text, ' '), '') FROM keystore_org_keys r`,
		`SELECT coalesce(string_agg(r::text, ' '), '') FROM device_encrypted_volumes r`,
		`SELECT coalesce(string_agg(r::text, ' '), '') FROM audit_log r`,
	} {
		dump.WriteString(f.str(q))
	}
	for _, p := range []string{password1, strings.ReplaceAll(password1, "-", "")} {
		if strings.Contains(dump.String(), p) {
			t.Fatal("the recovery password is in the database in clear")
		}
	}
	if got := f.str(`SELECT string_agg(action, ',' ORDER BY id) FROM audit_log WHERE action LIKE 'recovery_key.%'`); got != "recovery_key.escrowed,recovery_key.verified,recovery_key.verified" {
		t.Errorf("audit actions = %s", got)
	}
}

func TestEscrowMismatchIsStaleAndNothingGoodIsReplaced(t *testing.T) {
	f := newFx(t)
	dev := f.dv(f.dev, f.acme, f.hq)
	key, pub := f.instruction(dev)
	f.report(dev, f.vol, f.prot)

	// A record whose fingerprint is not its secret's: stale, send again.
	bad := f.record(dev, key, pub, f.vol, f.prot, password1)
	other := escrowcrypto.Fingerprint(f.prot, []byte(password2))
	bad.Fingerprint = hex.EncodeToString(other[:])
	ans, err := f.svc.Upload(f.ctx, dev, netip.Addr{}, bad)
	if err != nil || ans.State != agentproto.EscrowStale || !ans.Again {
		t.Fatalf("mismatch: %+v %v", ans, err)
	}
	// Within the limit, it cannot be spammed.
	if _, err := f.svc.Upload(f.ctx, dev, netip.Addr{}, f.record(dev, key, pub, f.vol, f.prot, password1)); !errors.Is(err, keystore.ErrTooFrequent) {
		t.Fatalf("limit: %v", err)
	}
	// The stale protector is asked for again once the wait has passed.
	f.later()
	if n := f.report(dev, f.vol, f.prot); len(n.Need) != 1 {
		t.Fatalf("a stale protector must be needed: %+v", n)
	}
	if ans, err := f.svc.Upload(f.ctx, dev, netip.Addr{}, f.record(dev, key, pub, f.vol, f.prot, password1)); err != nil || ans.State != agentproto.EscrowVerified {
		t.Fatalf("fix: %+v %v", ans, err)
	}
	if got := f.state(f.dev, f.prot); got != "superseded,verified" {
		t.Fatalf("state = %s", got)
	}

	// A valid record of ANOTHER secret for the same protector does not replace
	// the verified one: it is stored as a conflict beside it.
	f.later()
	ans, err = f.svc.Upload(f.ctx, dev, netip.Addr{}, f.record(dev, key, pub, f.vol, f.prot, password2))
	if err != nil || ans.State != agentproto.EscrowConflict {
		t.Fatalf("conflict: %+v %v", ans, err)
	}
	if got := f.state(f.dev, f.prot); got != "superseded,verified,conflict" {
		t.Fatalf("after conflict: %s", got)
	}
	// And a junk record cannot destroy it either.
	f.later()
	junk := f.record(dev, key, pub, f.vol, f.prot, password2)
	junk.Fingerprint = hex.EncodeToString(other[:1]) + strings.Repeat("0", 30)
	if ans, err := f.svc.Upload(f.ctx, dev, netip.Addr{}, junk); err != nil || ans.State != agentproto.EscrowStale {
		t.Fatalf("junk next to a verified record: %+v %v", ans, err)
	}
	if got := f.str(`SELECT count(*)::text FROM recovery_key_escrows WHERE device_id = $1 AND state = 'verified'`, f.dev); got != "1" {
		t.Fatalf("the verified record was lost: %s", got)
	}
	st, err := f.svc.DeviceState(f.ctx, access.System("test"), f.dev)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Volumes) != 1 || st.Volumes[0].State != keystore.StateConflict || st.Volumes[0].Protectors[0].State != keystore.StateConflict {
		t.Fatalf("the console must show the conflict: %+v", st.Volumes)
	}
	if got := f.str(`SELECT string_agg(action, ',' ORDER BY id) FROM audit_log WHERE action = 'recovery_key.conflict'`); got == "" {
		t.Error("the conflict was not audited")
	}
}

// A record copied to another device does not verify: the context binds it.
func TestEscrowRecordCopiedToAnotherDeviceFails(t *testing.T) {
	f := newFx(t)
	a, b := f.dv(f.dev, f.acme, f.hq), f.dv(f.dev2, f.acme, f.hq)
	key, pub := f.instruction(a)
	f.report(a, f.vol, f.prot)
	f.report(b, f.vol, f.prot)
	// Device A's genuine record, uploaded by device B.
	rec := f.record(a, key, pub, f.vol, f.prot, password1)
	ans, err := f.svc.Upload(f.ctx, b, netip.Addr{}, rec)
	if err != nil || ans.State != agentproto.EscrowStale {
		t.Fatalf("a copied record: %+v %v", ans, err)
	}
	if f.state(f.dev2, f.prot) != "stale" {
		t.Fatal("the copy was not stale")
	}
	// Another volume's, too.
	f.report(a, `\\?\Volume{22222222-2222-2222-2222-222222222222}\`, f.prot)
	rec.VolumeID = `\\?\Volume{22222222-2222-2222-2222-222222222222}\`
	if ans, err := f.svc.Upload(f.ctx, a, netip.Addr{}, rec); err != nil || ans.State != agentproto.EscrowStale {
		t.Fatalf("a copy to another volume: %+v %v", ans, err)
	}
}

func TestEscrowLimitsAndKey(t *testing.T) {
	f := newFx(t)
	dev := f.dv(f.dev, f.acme, f.hq)
	key, pub := f.instruction(dev)
	f.report(dev, f.vol, f.prot)
	rec := f.record(dev, key, pub, f.vol, f.prot, password1)

	// A record sealed to another key id than the organization's current one.
	old := rec
	old.KeyID = uuid.NewString()
	if _, err := f.svc.Upload(f.ctx, dev, netip.Addr{}, old); !errors.Is(err, keystore.ErrKeyOutdated) {
		t.Fatalf("outdated key: %v", err)
	}
	for _, mut := range []func(*agentproto.EscrowRecord){
		func(r *agentproto.EscrowRecord) { r.Kind = "luks" },
		func(r *agentproto.EscrowRecord) { r.Enc = "AAAA" },
		func(r *agentproto.EscrowRecord) { r.Fingerprint = "zz" },
	} {
		bad := rec
		mut(&bad)
		if _, err := f.svc.Upload(f.ctx, dev, netip.Addr{}, bad); !errors.Is(err, keystore.ErrRecordMismatch) {
			t.Fatalf("malformed: %v", err)
		}
	}
	// Twenty an hour per device.
	for i := range keystore.DeviceHourMax {
		f.exec(`INSERT INTO recovery_key_escrows (organization_id, site_id, device_id, volume_id, kind, protector_id, org_key_id, enc, ciphertext, fingerprint, state, created_at)
			SELECT $1, $2, $3, $4, 'bitlocker', $5, id, decode(repeat('00', 32), 'hex'), decode('00', 'hex'), decode(repeat('00', 16), 'hex'), 'superseded', now() - interval '10 minutes'
			FROM keystore_org_keys LIMIT 1`, f.acme, f.hq, f.dev, f.vol, fmt.Sprintf("{old-%d}", i))
	}
	if _, err := f.svc.Upload(f.ctx, dev, netip.Addr{}, rec); !errors.Is(err, keystore.ErrTooFrequent) {
		t.Fatalf("hourly limit: %v", err)
	}
}

// While the keystore is away the record is kept as pending, and checked when
// it returns.
func TestEscrowPendingWhileKeystoreIsAway(t *testing.T) {
	f := newFx(t)
	dev := f.dv(f.dev, f.acme, f.hq)
	key, pub := f.instruction(dev)
	f.report(dev, f.vol, f.prot)
	f.stopSocket()
	ans, err := f.svc.Upload(f.ctx, dev, netip.Addr{}, f.record(dev, key, pub, f.vol, f.prot, password1))
	if err != nil || ans.State != agentproto.EscrowPending {
		t.Fatalf("while away: %+v %v", ans, err)
	}
	if f.state(f.dev, f.prot) != "pending" {
		t.Fatal("not stored as pending")
	}
	// A pending protector is not asked for again.
	f.later()
	if n := f.report(dev, f.vol, f.prot); len(n.Need) != 0 {
		t.Fatalf("pending must not be needed: %+v", n)
	}
	f.startSocket()
	f.svc.RefreshStatus(f.ctx)
	if n, err := f.svc.VerifyPending(f.ctx); err != nil || n != 1 {
		t.Fatalf("verify pending: %d %v", n, err)
	}
	if f.state(f.dev, f.prot) != "verified" {
		t.Fatalf("state = %s", f.state(f.dev, f.prot))
	}
	// An organization outside the dev scope is left alone.
	defer devscope.Set(f.globex)()
	if n, _ := f.svc.VerifyPending(f.ctx); n != 0 {
		t.Fatal("verified again")
	}
}

func TestDeviceStateAndIsolation(t *testing.T) {
	f := newFx(t)
	dev := f.dv(f.dev, f.acme, f.hq)
	key, pub := f.instruction(dev)

	// A volume with no recovery-password protector is missing, and so is a
	// protector with no record.
	if _, err := f.svc.ReportVolumes(f.ctx, dev, agentproto.EscrowVolumesReport{Volumes: []agentproto.EscrowVolume{
		{ID: f.vol, Mount: "C:", Status: "encrypted", Protectors: []agentproto.EscrowProtector{{ID: f.prot}}},
		{ID: "vol-bare", Mount: "D:", Status: "encrypted"},
	}}); err != nil {
		t.Fatal(err)
	}
	user := func(org uuid.UUID) access.Caller {
		uid := f.id(`INSERT INTO users (email, display_name) VALUES ($1, $1) RETURNING id`, org.String()+"@example.com")
		p, err := rbac.NewPrincipal(uid, []rbac.Assignment{{Role: rbac.RoleTechnician, OrganizationID: org}})
		if err != nil {
			t.Fatal(err)
		}
		return access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: uid})
	}
	acmeTech, globexTech := user(f.acme), user(f.globex)
	st, err := f.svc.DeviceState(f.ctx, acmeTech, f.dev)
	if err != nil || !st.Applicable || len(st.Volumes) != 2 {
		t.Fatalf("state: %+v %v", st, err)
	}
	for _, v := range st.Volumes {
		if v.State != keystore.StateMissing {
			t.Errorf("volume %s = %s, want missing", v.ID, v.State)
		}
	}
	if _, err := f.svc.Upload(f.ctx, dev, netip.Addr{}, f.record(dev, key, pub, f.vol, f.prot, password1)); err != nil {
		t.Fatal(err)
	}
	st, _ = f.svc.DeviceState(f.ctx, acmeTech, f.dev)
	got := map[string]string{}
	for _, v := range st.Volumes {
		got[v.ID] = v.State
	}
	if got[f.vol] != keystore.StateVerified || got["vol-bare"] != keystore.StateMissing {
		t.Fatalf("states = %v", got)
	}
	// Another organization's technician sees nothing of it.
	if _, err := f.svc.DeviceState(f.ctx, globexTech, f.dev); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("another organization: %v", err)
	}
	// Row-level security, below the service: a scope of another organization
	// sees no row of any of the tables.
	for _, table := range []string{"recovery_key_escrows", "keystore_org_keys", "device_encrypted_volumes"} {
		var n int
		err := f.db.ReadTx(f.ctx, database.Scope{Orgs: []uuid.UUID{f.globex}}, func(tx pgx.Tx) error {
			return tx.QueryRow(f.ctx, `SELECT count(*) FROM `+table).Scan(&n)
		})
		if err != nil || n != 0 {
			t.Errorf("%s visible to another organization: %d %v", table, n, err)
		}
		err = f.db.ReadTx(f.ctx, database.Scope{Orgs: []uuid.UUID{f.acme}}, func(tx pgx.Tx) error {
			return tx.QueryRow(f.ctx, `SELECT count(*) FROM `+table).Scan(&n)
		})
		if err != nil || n == 0 {
			t.Errorf("%s not visible to its own organization: %d %v", table, n, err)
		}
	}
	// And a non-system scope cannot write them.
	err = f.db.InTx(f.ctx, database.Scope{Orgs: []uuid.UUID{f.acme}}, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `DELETE FROM recovery_key_escrows`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := f.str(`SELECT count(*)::text FROM recovery_key_escrows`); n == "0" {
		t.Error("an organization scope deleted escrow rows")
	}
	// A device that does not run Windows has nothing to show.
	lin := f.device(f.acme, f.hq, "lin", "linux")
	if st, _ := f.svc.DeviceState(f.ctx, acmeTech, lin); st == nil || st.Applicable {
		t.Errorf("linux device applicable: %+v", st)
	}
}

func TestKeystoreSummaryNeedsPlatformRight(t *testing.T) {
	f := newFx(t)
	uid := f.id(`INSERT INTO users (email, display_name) VALUES ('t@example.com', 't') RETURNING id`)
	p, _ := rbac.NewPrincipal(uid, []rbac.Assignment{{Role: rbac.RoleTechnician, OrganizationID: f.acme}})
	tech := access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: uid})
	if _, err := f.svc.Platform(f.ctx, tech); err == nil {
		t.Fatal("a technician read the keystore's platform status")
	}
	st, err := f.svc.Platform(f.ctx, access.System("test"))
	if err != nil || st.State != keystore.StateUnsealed || !st.RecoveryVerified {
		t.Fatalf("status: %+v %v", st, err)
	}
	if f.str(`SELECT count(*)::text FROM keystore_kek_versions WHERE recovery_verified_at IS NOT NULL`) != "1" {
		t.Error("the KEK version's metadata was not mirrored")
	}
}
