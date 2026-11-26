//go:build integration

package jobs

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/agent/escrow"
	"github.com/paulmataruso/easyrmm/agent/host"
	agentjobs "github.com/paulmataruso/easyrmm/agent/jobs"
	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/keystore"
	"github.com/paulmataruso/easyrmm/server/internal/keystored"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/bitlocker"
)

// ADR-0081 slice 4: BitLocker's enable action through the real path: the
// permission, the typed name, the step-up, the verified-escrow gate, the job
// the real agent worker runs as native code against a stand-in for WMI, and the
// real keystore (on a real socket) that verifies the escrowed password before
// the stand-in is told to encrypt.

// bitlockerSim stands in for WMI, which Linux does not have. It is the
// computer: its volumes, its protectors and their passwords, and the order in
// which the agent changed it.
type bitlockerSim struct {
	mu       sync.Mutex
	computer string
	dc       bool
	tpm      bool
	reboot   bool
	vols     map[string]*simVolume // by drive letter
	events   []string
	pwSeq    int
	// atEncrypt is called, with the lock released, when encryption starts.
	atEncrypt func(volume string)
}

type simVolume struct {
	id, letter, status string
	protectors         map[string]string // numerical-password protector ID to password
	tpmProt            bool
}

func newSim() *bitlockerSim {
	s := &bitlockerSim{computer: "HQ-PC", tpm: true, vols: map[string]*simVolume{}}
	s.vols["C:"] = &simVolume{id: `\\?\Volume{c0000000-0000-0000-0000-000000000001}\`, letter: "C:", status: "decrypted", protectors: map[string]string{}}
	s.vols["D:"] = &simVolume{id: `\\?\Volume{d0000000-0000-0000-0000-000000000002}\`, letter: "D:", status: "decrypted", protectors: map[string]string{}}
	return s
}

func (s *bitlockerSim) log(e string) { s.events = append(s.events, e) }

func (s *bitlockerSim) Volumes(context.Context) ([]escrow.Volume, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []escrow.Volume
	for _, l := range []string{"C:", "D:"} {
		v := s.vols[l]
		ev := escrow.Volume{ID: v.id, Mount: v.letter, Status: v.status}
		for id := range v.protectors {
			ev.Protectors = append(ev.Protectors, id)
		}
		out = append(out, ev)
	}
	return out, nil
}

func (s *bitlockerSim) RecoveryPassword(_ context.Context, volumeID, protectorID string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.vols {
		if v.id == volumeID {
			if pw, ok := v.protectors[protectorID]; ok {
				return []byte(pw), nil
			}
		}
	}
	return nil, fmt.Errorf("no such protector")
}

func (s *bitlockerSim) Preconditions(context.Context) (escrow.Preconditions, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return escrow.Preconditions{Computer: s.computer, DomainController: s.dc, TPMReady: s.tpm, EditionAllows: true, RebootPending: s.reboot}, nil
}

func (s *bitlockerSim) Volume(_ context.Context, letter string) (*escrow.VolumeInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.vols[strings.ToUpper(letter)]
	if v == nil {
		return nil, nil
	}
	info := &escrow.VolumeInfo{ID: v.id, Mount: v.letter, Status: v.status, AnyProtectors: len(v.protectors) > 0 || v.tpmProt}
	for id := range v.protectors {
		info.Protectors = append(info.Protectors, id)
	}
	return info, nil
}

func (s *bitlockerSim) byID(id string) *simVolume {
	for _, v := range s.vols {
		if v.id == id {
			return v
		}
	}
	return nil
}

func (s *bitlockerSim) AddRecoveryPassword(_ context.Context, volumeID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.byID(volumeID)
	s.pwSeq++
	id := fmt.Sprintf("{00000000-0000-4000-8000-%012d}", s.pwSeq)
	// A BitLocker numerical password: eight groups of six digits, each a
	// multiple of eleven.
	pw := make([]string, 8)
	for i := range pw {
		pw[i] = fmt.Sprintf("%06d", (s.pwSeq*7+i*13+100)%90000/11*11+11)
	}
	v.protectors[id] = strings.Join(pw, "-")
	s.log("add_recovery_password:" + v.letter)
	return id, nil
}

func (s *bitlockerSim) DeleteProtector(_ context.Context, volumeID, protectorID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.byID(volumeID)
	delete(v.protectors, protectorID)
	s.log("delete_protector:" + v.letter)
	return nil
}

func (s *bitlockerSim) AddTPMProtector(_ context.Context, volumeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.byID(volumeID)
	v.tpmProt = true
	s.log("add_tpm:" + v.letter)
	return nil
}

func (s *bitlockerSim) StartEncryption(_ context.Context, volumeID string, usedOnly bool) error {
	s.mu.Lock()
	v := s.byID(volumeID)
	s.log(fmt.Sprintf("encrypt:%s:used_only=%v", v.letter, usedOnly))
	v.status = "encrypting"
	cb := s.atEncrypt
	s.mu.Unlock()
	if cb != nil {
		cb(v.letter)
	}
	return nil
}

func (s *bitlockerSim) eventsString() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.events, ",")
}

// ksAgentServer is the agent's routes, answered by the real service.
type ksAgentServer struct {
	svc    *keystore.Service
	dev    keystore.Device
	tamper bool
}

func (k *ksAgentServer) EscrowVolumes(ctx context.Context, rep agentproto.EscrowVolumesReport) (agentproto.EscrowVolumesAnswer, error) {
	return k.svc.ReportVolumes(ctx, k.dev, rep)
}

func (k *ksAgentServer) EscrowUpload(ctx context.Context, rec agentproto.EscrowRecord) (agentproto.EscrowAnswer, error) {
	if k.tamper {
		// A fingerprint of another password: the keystore opens the record,
		// computes its own and says it does not match.
		rec.Fingerprint = strings.Repeat("ab", 16)
	}
	return k.svc.Upload(ctx, k.dev, netip.Addr{}, rec)
}

// nativeClient is an agent that announces the native capability, which the
// build running these tests (Linux) does not.
type nativeClient struct{ agentClient }

func (n nativeClient) Poll(ctx context.Context, accepts []string) (*agentproto.PollResponse, error) {
	return n.s.Poll(ctx, n.dev, append(append([]string{}, accepts...), agentproto.CapJobNative))
}

type bitlockerFixture struct {
	*fixture
	ks    *keystore.Service
	sim   *bitlockerSim
	agent *escrow.Agent
	srv   *ksAgentServer
	dev   uuid.UUID
	admin access.Caller
	sock  string
}

func bitlockerFx(t *testing.T) *bitlockerFixture {
	t.Helper()
	f := newFixture(t)
	cat, err := winmod.NewCatalog(bitlocker.Actions()...)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	f.svc.SetWinmod(cat, modules.New(f.db, audit.New(f.db, time.Now), log), nil)
	f.svc.SetStepUp(stepUpStub{})

	// A real keystore on a real socket, in file mode.
	dir := t.TempDir()
	k, err := keystored.Open(keystored.Options{Dir: filepath.Join(dir, "state"), Mode: keystore.ModeFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Close)
	code, bf, err := k.Init("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.VerifyRecovery(bf, code); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "ks.sock")
	ln, err := keystored.Listen(sock, 0o660)
	if err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid()) //nolint:gosec // a uid
	srv := &keystored.Server{KS: k, ServiceUIDs: []uint32{uid}, AdminUID: uid}
	sctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Serve(sctx, ln, nil); close(done) }()
	t.Cleanup(func() { stop(); <-done })

	signPub, signKey, _ := ed25519.GenerateKey(rand.Reader)
	ks := keystore.New(f.db, audit.New(f.db, nil), &keystore.Client{Path: sock, Timeout: 10 * time.Second}, signKey, log)
	f.svc.SetEscrowGate(ks)

	dev := f.winmodDevice("HQ-PC", "windows")
	if _, err := f.svc.Poll(f.ctx, dev, []string{agentproto.CapJobPwsh, agentproto.CapJobParams, agentproto.CapJobNative}); err != nil {
		t.Fatal(err)
	}
	var org, site uuid.UUID
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT organization_id, site_id FROM devices WHERE id = $1`, dev).Scan(&org, &site)
	}); err != nil {
		t.Fatal(err)
	}
	d := keystore.Device{ID: dev, Org: org, Site: site, Hostname: "HQ-PC"}
	sim := newSim()
	srvAgent := &ksAgentServer{svc: ks, dev: d}
	store, _, err := state.Open(host.Paths{Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store.Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	a := &escrow.Agent{DeviceID: dev.String(), Key: func() ed25519.PublicKey { return signPub }, Reader: sim, Manager: sim, Server: srvAgent, Store: store, Log: log}
	if s := ks.Instruction(f.ctx, d, "windows", []string{agentproto.CapEscrow}); s != nil {
		a.Answered(s)
	} else {
		t.Fatal("the keystore gave no escrow key")
	}
	admin := f.user("admin@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	return &bitlockerFixture{fixture: f, ks: ks, sim: sim, agent: a, srv: srvAgent, dev: dev, admin: admin, sock: sock}
}

// runWorker has the real agent worker take the device's jobs with the real
// native handler until the run ends, and returns the run's typed result.
func (b *bitlockerFixture) enable(params, confirm string) (*WinmodResult, error) {
	b.t.Helper()
	run, err := b.svc.RunWinmod(b.ctx, b.admin, WinmodInput{DeviceID: b.dev, Action: "bitlocker.enable", Params: json.RawMessage(params), Confirm: confirm})
	if err != nil {
		return nil, err
	}
	w := &agentjobs.Worker{
		Client: nativeClient{agentClient{b.svc, b.dev}}, DeviceID: b.dev.String(), Dir: b.t.TempDir(), Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		MinRetry: 10 * time.Millisecond, MaxRetry: 50 * time.Millisecond,
	}
	w.Execute = agentjobs.WithNative(agentjobs.Execute, map[string]agentjobs.NativeHandler{
		agentproto.NativeBitLockerEnable: func(ctx context.Context, params []byte) string {
			var p agentproto.BitLockerEnableParams
			if err := json.Unmarshal(params, &p); err != nil {
				return agentproto.NativeResult(1, nil, "bad_params", "x")
			}
			return b.agent.EnableBitLocker(ctx, p)
		},
	})
	if err := w.SetKey(agentproto.EncodeKey(b.key)); err != nil {
		b.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(b.ctx)
	done := make(chan struct{})
	go func() { _ = w.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		st := b.str(`SELECT status FROM job_runs WHERE id = $1`, run.RunID)
		if st == "succeeded" || st == "failed" {
			break
		}
		if time.Now().After(deadline) {
			b.t.Fatalf("the run did not end: %s", st)
		}
	}
	return b.svc.ReadWinmodResult(b.ctx, b.admin, run.RunID)
}

const enableParams = `{"computer":"HQ-PC","volume":"C:"}`
const enableConfirm = "bitlocker.enable:HQ-PC"

func TestBitLockerEnableRefusalsMakeNoJob(t *testing.T) {
	b := bitlockerFx(t)
	tech := b.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: b.acme, SiteID: b.hq})
	siteAdmin := b.user("sa@example.com", rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: b.acme, SiteID: b.hq})
	run := func(c access.Caller, params, confirm string) error {
		_, err := b.svc.RunWinmod(b.ctx, c, WinmodInput{DeviceID: b.dev, Action: "bitlocker.enable", Params: json.RawMessage(params), Confirm: confirm})
		return err
	}
	jobs := func() int { return b.count(`SELECT count(*) FROM jobs WHERE kind = 'winmod'`) }

	// The permission: a technician and a site administrator do not hold it.
	for name, c := range map[string]access.Caller{"technician": tech, "site administrator": siteAdmin} {
		if err := run(c, enableParams, enableConfirm); err == nil {
			t.Errorf("a %s turned BitLocker on", name)
		}
	}
	// The typed confirmation names the action and the computer.
	for _, confirm := range []string{"", "bitlocker.enable", "bitlocker.enable:OTHER"} {
		fieldErr(t, run(b.admin, enableParams, confirm), "confirm", enableConfirm)
	}
	// The computer must be the real one.
	fieldErr(t, run(b.admin, `{"computer":"OTHER","volume":"C:"}`, "bitlocker.enable:OTHER"), "confirm", "not the computer's name")
	// Bad parameters.
	for _, p := range []string{`{"computer":"HQ-PC","volume":"C:\\"}`, `{"computer":"HQ-PC","volume":"CD"}`, `{"computer":"HQ-PC","volume":"C:","encryption":"half"}`, `{"computer":"HQ-PC"}`} {
		if err := run(b.admin, p, enableConfirm); err == nil {
			t.Errorf("%s was accepted", p)
		}
	}
	// A step-up that is not fresh.
	b.svc.SetStepUp(stepUpStub{err: errors.New("step up required")})
	if err := run(b.admin, enableParams, enableConfirm); err == nil {
		t.Error("turned on without a step-up")
	}
	b.svc.SetStepUp(stepUpStub{})
	// An organization outside the development scope is not found.
	restore := devscope.Set(uuid.New())
	err := run(b.admin, enableParams, enableConfirm)
	restore()
	if err == nil {
		t.Error("turned on outside the dev scope")
	}
	if jobs() != 0 {
		t.Fatalf("%d jobs were made by refused requests", jobs())
	}
	// The gate: a keystore that cannot verify makes no job. A second service on
	// a socket nobody listens on is that keystore.
	gone := keystore.New(b.db, audit.New(b.db, nil), &keystore.Client{Path: filepath.Join(t.TempDir(), "none.sock"), Timeout: time.Second}, nil, slog.New(slog.DiscardHandler))
	b.svc.SetEscrowGate(gone)
	if err := run(b.admin, enableParams, enableConfirm); err == nil {
		t.Error("turned on with no keystore to verify the key")
	}
	b.svc.SetEscrowGate(nil)
	if err := run(b.admin, enableParams, enableConfirm); err == nil {
		t.Error("turned on with no escrow gate configured")
	}
	if jobs() != 0 {
		t.Fatalf("%d jobs were made with no gate", jobs())
	}
	b.svc.SetEscrowGate(b.ks)
	if err := run(b.admin, enableParams, enableConfirm); err != nil {
		t.Fatalf("the allowed request: %v", err)
	}
	// It is a native job: the shell, the handler, the capabilities it needs, no
	// script, and an audit row with the confirmation and step-up recorded.
	if got := b.str(`SELECT shell || '|' || body || '|' || array_to_string(requires, ',') FROM jobs WHERE kind = 'winmod'`); got != "native|bitlocker.enable|job.native,job.params" {
		t.Errorf("job: %s", got)
	}
	au := b.str(`SELECT details::text FROM audit_log WHERE action = 'winmod.bitlocker.enable'`)
	if !strings.Contains(au, `"destructive": true`) || !strings.Contains(au, `"stepUp": true`) || !strings.Contains(au, `"confirmed": true`) {
		t.Errorf("audit: %s", au)
	}
}

func TestBitLockerEnableEscrowsAndVerifiesBeforeEncrypting(t *testing.T) {
	b := bitlockerFx(t)
	var verifiedAtEncrypt int
	b.sim.atEncrypt = func(string) {
		verifiedAtEncrypt = b.count(`SELECT count(*) FROM recovery_key_escrows WHERE state = 'verified'`)
	}
	res, err := b.enable(enableParams, enableConfirm)
	if err != nil || res.OK == nil || !*res.OK {
		t.Fatalf("result: %+v %v", res, err)
	}
	var got bitlocker.Enable
	if err := json.Unmarshal(res.Data, &got); err != nil || got != (bitlocker.Enable{Volume: "C:", Escrow: "verified", Encryption: "started", Mode: "used_space"}) {
		t.Fatalf("data: %s %v", res.Data, err)
	}
	// The order the ADR fixes, and the verified record already stored when
	// encryption began.
	if ev := b.sim.eventsString(); ev != "add_recovery_password:C:,add_tpm:C:,encrypt:C::used_only=true" {
		t.Fatalf("events: %s", ev)
	}
	if verifiedAtEncrypt != 1 {
		t.Fatalf("%d verified records when encryption started", verifiedAtEncrypt)
	}
	// What the keystore holds is the password the computer made.
	var pw string
	for _, p := range b.sim.vols["C:"].protectors {
		pw = p
	}
	if st := b.str(`SELECT state FROM recovery_key_escrows`); st != "verified" {
		t.Fatalf("state %s", st)
	}
	// The password is in no job, run, result or audit row.
	for _, q := range []string{
		`SELECT coalesce(string_agg(params::text || coalesce(body, ''), ' '), '') FROM jobs`,
		`SELECT coalesce(string_agg(error, ' '), '') FROM job_runs`,
		`SELECT coalesce(string_agg(coalesce(data::text, '') || coalesce(error::text, ''), ' '), '') FROM winmod_run_results`,
		`SELECT coalesce(string_agg(details::text, ' '), '') FROM audit_log`,
		`SELECT coalesce(string_agg(enc::text || ciphertext::text || fingerprint::text, ' '), '') FROM recovery_key_escrows`,
	} {
		if s := b.str(q); strings.Contains(s, pw) || strings.Contains(s, strings.ReplaceAll(pw, "-", "")) {
			t.Errorf("the recovery password is in: %.60s", q)
		}
	}
	if b.count(`SELECT count(*) FROM job_runs WHERE stdout_bytes + stderr_bytes > 0`) != 0 {
		t.Error("raw output was kept")
	}
}

func TestBitLockerEnableNeverEncryptsWhatTheServerDidNotVerify(t *testing.T) {
	b := bitlockerFx(t)
	b.srv.tamper = true
	res, err := b.enable(enableParams, enableConfirm)
	if err != nil || res.OK == nil || *res.OK {
		t.Fatalf("result: %+v %v", res, err)
	}
	if !strings.Contains(string(res.Failure), "escrow_unverified") {
		t.Fatalf("failure: %s", res.Failure)
	}
	// The protector it added is removed again (it is not escrowed) and the TPM
	// protector and encryption never came.
	if ev := b.sim.eventsString(); ev != "add_recovery_password:C:,delete_protector:C:" {
		t.Fatalf("events: %s", ev)
	}
	if b.count(`SELECT count(*) FROM recovery_key_escrows WHERE state = 'verified'`) != 0 {
		t.Error("a record that did not match was verified")
	}
}

func TestBitLockerEnableAgentSidePreconditions(t *testing.T) {
	cases := map[string]struct {
		mut  func(*bitlockerSim)
		code string
	}{
		"a domain controller":  {func(s *bitlockerSim) { s.dc = true }, "domain_controller"},
		"no TPM":               {func(s *bitlockerSim) { s.tpm = false }, "tpm_not_ready"},
		"a restart is pending": {func(s *bitlockerSim) { s.reboot = true }, "reboot_pending"},
		"another computer":     {func(s *bitlockerSim) { s.computer = "OTHER-PC" }, "wrong_computer"},
		"already encrypted":    {func(s *bitlockerSim) { s.vols["C:"].status = "encrypted" }, "already_encrypted"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			b := bitlockerFx(t)
			c.mut(b.sim)
			res, err := b.enable(enableParams, enableConfirm)
			if err != nil || res.OK == nil || *res.OK || !strings.Contains(string(res.Failure), c.code) {
				t.Fatalf("result: %+v %v", res, err)
			}
			if ev := b.sim.eventsString(); ev != "" {
				t.Fatalf("the computer was changed: %s", ev)
			}
		})
	}
}

func TestNativeJobIsNotSentToAnAgentThatLacksTheCapability(t *testing.T) {
	b := bitlockerFx(t)
	if _, err := b.svc.RunWinmod(b.ctx, b.admin, WinmodInput{DeviceID: b.dev, Action: "bitlocker.enable", Params: json.RawMessage(enableParams), Confirm: enableConfirm}); err != nil {
		t.Fatal(err)
	}
	resp, err := b.svc.Poll(b.ctx, b.dev, []string{agentproto.CapJobPwsh, agentproto.CapJobParams})
	if err != nil || len(resp.Jobs) != 0 {
		t.Fatalf("an agent without job.native was sent %d jobs (%v)", len(resp.Jobs), err)
	}
	resp, err = b.svc.Poll(b.ctx, b.dev, []string{agentproto.CapJobParams, agentproto.CapJobNative})
	if err != nil || len(resp.Jobs) != 1 {
		t.Fatalf("an agent with it was sent %d jobs (%v)", len(resp.Jobs), err)
	}
	p, err := agentproto.VerifyJob(b.key, resp.Jobs[0], b.dev.String(), time.Now())
	if err != nil || p.Shell != agentproto.ShellNative || p.Script != agentproto.NativeBitLockerEnable || p.V != agentproto.JobPayloadVersionParams {
		t.Fatalf("payload %+v %v", p, err)
	}
	// A person cannot make a native job out of a script: the shell is not one.
	if agentproto.ValidShell(agentproto.ShellNative) {
		t.Fatal("native is a shell a person may give a script")
	}
}
