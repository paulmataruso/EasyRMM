//go:build integration

package agents

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/jobkeys"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
)

// keyed is the updates fixture with a real ring of job keys behind the
// service (ADR-0057), and a clock the ring follows.
type keyed struct {
	*updates
	ring   *jobkeys.Ring
	sealer *secrets.Sealer
	k1     jobkeys.Key
}

func newKeyed(t *testing.T) *keyed {
	t.Helper()
	u := newUpdates(t, "new build", "v2")
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	sealer, err := secrets.NewSealer(secrets.Key{ID: "k1", Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	ring, err := jobkeys.Open(u.ctx, u.db, sealer, slog.New(slog.NewTextHandler(io.Discard, nil)),
		jobkeys.Options{Version: "test", Audit: audit.New(u.db, nil), Now: func() time.Time { return u.clock }})
	if err != nil {
		t.Fatal(err)
	}
	u.svc.SetUpdates(u.svc.builds, ring)
	u.svc.SetKeys(ring)
	u.pub = ring.Newest().Public
	return &keyed{updates: u, ring: ring, sealer: sealer, k1: ring.Newest()}
}

// beatWith sends a heartbeat with extra request fields and returns the answer.
func (f *keyed) beatWith(d *Device, sha string, mutate func(*agentproto.HeartbeatRequest)) *agentproto.HeartbeatResponse {
	f.t.Helper()
	req := agentproto.HeartbeatRequest{Facts: agentproto.Facts{Hostname: "h", Platform: "linux", Arch: "amd64", AgentVersion: "v1", AgentSHA256: sha}}
	if mutate != nil {
		mutate(&req)
	}
	resp, err := f.svc.Heartbeat(f.ctx, d, netip.MustParseAddr("192.0.2.10"), req)
	if err != nil {
		f.t.Fatal(err)
	}
	return resp
}

func (f *keyed) report(keys ...jobkeys.Key) []agentproto.TrustedKey {
	out := make([]agentproto.TrustedKey, len(keys))
	for i, k := range keys {
		out[i] = agentproto.TrustedKey{Key: k.Encoded(), Generation: k.Generation}
	}
	return out
}

// secondKey adds a second key to the ring, as a rotation will.
func (f *keyed) secondKey() jobkeys.Key {
	f.t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	gen := f.clock.UnixMilli()
	sealed, err := f.sealer.Seal(priv.Seed(), []byte("easyrmm:job_key:"+itoa(gen)))
	if err != nil {
		f.t.Fatal(err)
	}
	f.exec(`INSERT INTO job_keys (generation, public_key, sealed_seed, reason) VALUES ($1, $2, $3, 'planned')`, gen, []byte(priv.Public().(ed25519.PublicKey)), sealed)
	if err := f.ring.Reload(f.ctx); err != nil {
		f.t.Fatal(err)
	}
	return f.ring.Newest()
}

func itoa(n int64) string {
	b := make([]byte, 0, 20)
	if n == 0 {
		return "0"
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func logOf(acked uint64, e ...agentproto.LoggedInstruction) *agentproto.InstructionLogReport {
	return &agentproto.InstructionLogReport{Acked: acked, Entries: e}
}

func TestEnrollmentAndHeartbeatAnswersCarryTheKeyAndTheFeature(t *testing.T) {
	f := newKeyed(t)
	tok, err := f.svc.CreateToken(f.ctx, f.sys, f.hq, TokenInput{Name: "t", ExpiresInDays: 1})
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	resp, err := f.svc.Enroll(f.ctx, agentIP, agentproto.EnrollRequest{Token: tok.Secret,
		PublicKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
		Facts:     agentproto.Facts{Hostname: "pc", Platform: "linux", Arch: "amd64", AgentVersion: "1"}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.JobKey != f.k1.Encoded() || resp.JobKeyGeneration != 1 {
		t.Fatalf("enrollment answer %q generation %d", resp.JobKey, resp.JobKeyGeneration)
	}
	if n := f.count(`SELECT count(*) FROM devices WHERE id = $1 AND job_key_given_generation = 1`, resp.DeviceID); n != 1 {
		t.Error("the key given at enrollment is not recorded")
	}
	d := f.auth(resp.DeviceID, key)
	ans := f.beatWith(d, oldSHA, nil)
	if ans.JobKey != f.k1.Encoded() || ans.JobKeyGeneration != 1 || !slices.Contains(ans.Features, agentproto.FeatureInstructionLog) || ans.InstructionAck != 0 {
		t.Fatalf("answer %q %d %v %d", ans.JobKey, ans.JobKeyGeneration, ans.Features, ans.InstructionAck)
	}
	// Nothing is stored from a heartbeat that carries no report.
	if n := f.count(`SELECT count(*) FROM devices WHERE id = $1 AND job_keys_report IS NULL`, d.ID); n != 1 {
		t.Error("a report appeared from nowhere")
	}
	// The report, the authorities and the log are stored and acknowledged.
	rogue, _, _ := ed25519.GenerateKey(rand.Reader)
	ans = f.beatWith(d, oldSHA, func(r *agentproto.HeartbeatRequest) {
		r.JobKeys = append(f.report(f.k1), agentproto.TrustedKey{Key: agentproto.EncodeKey(rogue), Generation: f.clock.UnixMilli()})
		r.Authorities = []string{"b", "a", "a"}
		r.InstructionLog = logOf(0, agentproto.LoggedInstruction{Seq: 1, Kind: agentproto.InstructionJob, ID: "never-issued", Signer: f.k1.Fingerprint(), At: f.clock})
	})
	if ans.InstructionAck != 1 || ans.JobKey != f.k1.Encoded() {
		t.Fatalf("answer %+v", ans)
	}
	if n := f.count(`SELECT count(*) FROM device_unknown_keys WHERE device_id = $1`, d.ID); n != 1 {
		t.Errorf("unknown keys %d", n)
	}
	if n := f.count(`SELECT count(*) FROM device_instruction_flags WHERE device_id = $1`, d.ID); n != 1 {
		t.Errorf("instruction flags %d", n)
	}
	if n := f.count(`SELECT count(*) FROM devices WHERE id = $1 AND agent_authorities = ARRAY['a','b']`, d.ID); n != 1 {
		t.Error("the authorities were not stored sorted and without duplicates")
	}
	// A statement the agent refused is audited with its reason.
	f.clock = f.clock.Add(time.Second)
	f.beatWith(d, oldSHA, func(r *agentproto.HeartbeatRequest) {
		r.KeyRefused = &agentproto.KeyRefusal{Statement: agentproto.InstructionHandover, ID: "s-1", Reason: "signature"}
	})
	if n := f.audited("device.job_key_refused", d.ID); n != 1 {
		t.Errorf("refusal audited %d times", n)
	}
}

// ADR-0057's case: an agent update's first heartbeat on the new build carries
// no log and deletes the update's row; the second brings the entry, which is
// not flagged, since the server compares it with what it issued, not with the
// row that drove the work.
func TestAnUpdateIsNotFlaggedAfterItsRowIsDeleted(t *testing.T) {
	f := newKeyed(t)
	if _, err := f.svc.SetUpdatePolicy(f.ctx, f.sys, UpdatePolicy{Mode: UpdateAutomatic, MaxConcurrent: 2}); err != nil {
		t.Fatal(err)
	}
	d, _ := f.enroll(f.hq, "pc-1")
	p := f.heartbeat(d, oldSHA, nil)
	if p == nil {
		t.Fatal("no update instruction")
	}
	if n := f.count(`SELECT count(*) FROM issued_instructions WHERE device_id = $1 AND kind = 'update' AND instruction_id = $2 AND generation = 1`, d.ID, p.ID); n != 1 {
		t.Fatalf("the update was recorded %d times", n)
	}
	// Repeated while in flight: still one row.
	f.heartbeat(d, oldSHA, nil)
	if n := f.count(`SELECT count(*) FROM issued_instructions WHERE device_id = $1 AND kind = 'update'`, d.ID); n != 1 {
		t.Errorf("a repeat recorded %d rows", n)
	}
	// The device comes back on the new build, with no log; the row goes.
	f.beatWith(d, sum("new build"), nil)
	if n := f.count(`SELECT count(*) FROM agent_updates WHERE device_id = $1`, d.ID); n != 0 {
		t.Fatal("the update's row stayed")
	}
	f.beatWith(d, sum("new build"), func(r *agentproto.HeartbeatRequest) {
		r.InstructionLog = logOf(0, agentproto.LoggedInstruction{Seq: 1, Kind: agentproto.InstructionUpdate, ID: p.ID, Signer: f.k1.Fingerprint(), At: f.clock})
	})
	if n := f.count(`SELECT count(*) FROM device_instruction_flags WHERE device_id = $1`, d.ID); n != 0 {
		t.Errorf("a successful update was flagged")
	}
}

func TestUninstallsAreKnownAfterTheRemovalIsCancelledAndAfterTheDeviceIsDeleted(t *testing.T) {
	f := newKeyed(t)
	admin := f.user("admin@example.com", rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: f.org, SiteID: f.hq})
	d, _ := f.enroll(f.hq, "pc-1")
	if _, err := f.svc.RequestRemoval(f.ctx, admin, d.ID); err != nil {
		t.Fatal(err)
	}
	u := f.uninstallOf(d)
	if u == nil {
		t.Fatal("no uninstall instruction")
	}
	if err := f.svc.CancelRemoval(f.ctx, admin, d.ID); err != nil {
		t.Fatal(err)
	}
	f.beatWith(d, oldSHA, func(r *agentproto.HeartbeatRequest) {
		r.InstructionLog = logOf(0, agentproto.LoggedInstruction{Seq: 1, Kind: agentproto.InstructionUninstall, ID: u.ID, Signer: f.k1.Fingerprint(), At: f.clock})
	})
	if n := f.count(`SELECT count(*) FROM device_instruction_flags WHERE device_id = $1`, d.ID); n != 0 {
		t.Error("an uninstall whose removal was canceled was flagged")
	}
	// The issued rows have no foreign key: deleting the device keeps them.
	if err := f.svc.ForceRemove(f.ctx, admin, d.ID); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM issued_instructions WHERE device_id = $1 AND kind = 'uninstall' AND instruction_id = $2`, d.ID, u.ID); n != 1 {
		t.Errorf("the record went with the device: %d", n)
	}
}

func TestDownloadsAreSignedWithTheDevicesKeyAndRecordedByNonce(t *testing.T) {
	f := newKeyed(t)
	d, _ := f.enroll(f.hq, "pc-1")
	auth := agentproto.Auth{Device: d.ID.String(), Nonce: "nonce-1234567890ab"}
	p := &SignedRequest{auth: auth, device: *d}
	body := []byte("MeshID=0x1")
	sig := f.svc.SignDownload(f.ctx, p, agentproto.PathMeshSettings, body)
	if sig == "" {
		t.Fatal("not signed")
	}
	if err := agentproto.VerifyDownload(f.k1.Public, sig, d.ID.String(), agentproto.PathMeshSettings, auth.Nonce, sha256.Sum256(body)); err != nil {
		t.Fatalf("the signature does not verify with the ring's key: %v", err)
	}
	if n := f.count(`SELECT count(*) FROM issued_instructions WHERE device_id = $1 AND kind = 'download' AND instruction_id = $2`, d.ID, auth.Nonce); n != 1 {
		t.Errorf("recorded %d times", n)
	}
	// Without a key source nothing is signed.
	f.svc.SetUpdates(nil, nil)
	f.svc.SetKeys(nil)
	if sig := f.svc.SignDownload(f.ctx, p, agentproto.PathMeshSettings, body); sig != "" {
		t.Error("signed without a key")
	}
}

func TestTheAnswerIsSignedForWhatTheDeviceTrustsAndPollsReportToo(t *testing.T) {
	f := newKeyed(t)
	k2 := f.secondKey()
	d, _ := f.enroll(f.hq, "pc-1")
	// Trusting both keys, it is signed for with the newer.
	f.clock = f.clock.Add(time.Second)
	ans := f.beatWith(d, oldSHA, func(r *agentproto.HeartbeatRequest) { r.JobKeys = f.report(f.k1, k2) })
	if ans.JobKey != k2.Encoded() || ans.JobKeyGeneration != k2.Generation {
		t.Fatalf("answer key generation %d", ans.JobKeyGeneration)
	}
	// An older poll opened with the old report, arriving later, does not
	// write over the newer report.
	older := WithSignedAt(f.ctx, f.clock.Add(-time.Minute))
	f.svc.ObservePoll(older, d, f.report(f.k1))
	ans = f.beatWith(d, oldSHA, nil)
	if ans.JobKey != k2.Encoded() {
		t.Error("a stale poll's report changed the key")
	}
	// A newer poll's report counts.
	f.svc.ObservePoll(WithSignedAt(f.ctx, f.clock.Add(time.Minute)), d, f.report(f.k1))
	ans = f.beatWith(d, oldSHA, nil)
	if ans.JobKey != f.k1.Encoded() {
		t.Error("a newer poll's report was ignored")
	}
	f.svc.ObservePoll(f.ctx, d, nil) // no report: nothing
}

func TestARemovedDeviceIsAnsweredByItsLastReport(t *testing.T) {
	f := newKeyed(t)
	k2 := f.secondKey()
	admin := f.user("admin@example.com", rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: f.org, SiteID: f.hq})
	d, key := f.enroll(f.hq, "pc-1")
	f.beatWith(d, oldSHA, func(r *agentproto.HeartbeatRequest) { r.JobKeys = f.report(f.k1, k2) })
	if err := f.svc.ForceRemove(f.ctx, admin, d.ID); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM retired_devices WHERE device_id = $1 AND job_keys_report IS NOT NULL`, d.ID); n != 1 {
		t.Fatal("the removed device kept no report")
	}
	rd, err := f.svc.Authenticate(f.ctx, header(t, key, d.ID, f.clock), "POST", agentproto.PathHeartbeat, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := f.svc.RetiredHeartbeat(f.ctx, rd)
	if err != nil {
		t.Fatal(err)
	}
	if resp.JobKey != k2.Encoded() || resp.JobKeyGeneration != k2.Generation || resp.Uninstall == nil {
		t.Fatalf("answer %+v", resp)
	}
	if _, err := agentproto.VerifyUninstall(k2.Public, *resp.Uninstall, d.ID.String(), f.clock); err != nil {
		t.Errorf("the uninstall is not signed with the key it trusts: %v", err)
	}
	if n := f.count(`SELECT count(*) FROM issued_instructions WHERE device_id = $1 AND kind = 'uninstall' AND generation = $2`, d.ID, k2.Generation); n != 1 {
		t.Errorf("recorded %d", n)
	}
}

// A failure to store the report never fails the heartbeat, and a log that
// could not be stored is not acknowledged.
func TestAHeartbeatSurvivesWhatItCannotStore(t *testing.T) {
	f := newKeyed(t)
	d, _ := f.enroll(f.hq, "pc-1")
	// An entry dated beyond what the database can store fails the insert of
	// its flag.
	ans := f.beatWith(d, oldSHA, func(r *agentproto.HeartbeatRequest) {
		r.JobKeys = f.report(f.k1)
		r.InstructionLog = logOf(0, agentproto.LoggedInstruction{Seq: 1, Kind: "job", ID: "x", Signer: f.k1.Fingerprint(), At: time.Date(300000, 1, 1, 0, 0, 0, 0, time.UTC)})
	})
	if ans.InstructionAck != 0 || ans.JobKey != f.k1.Encoded() {
		t.Errorf("answer %+v", ans)
	}
	// The report that came with it is not stored either: one savepoint.
	if n := f.count(`SELECT count(*) FROM devices WHERE id = $1 AND job_keys_report IS NOT NULL`, d.ID); n != 0 {
		t.Error("a failed extra stored a report")
	}
}

var _ = uuid.Nil
var _ pgx.Tx
var _ = database.System
