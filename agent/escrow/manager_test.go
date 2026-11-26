package escrow_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/paulmataruso/easyrmm/agent/escrow"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

const (
	mgrVol   = `\\?\Volume{1}\`
	newProt  = "{NEW1}"
	newPass  = "111111-222222-333333-444444-555555-666666-777777-888888"
	computer = "HQ-PC"
)

// stubManager stands in for WMI: it changes the volumes the stubReader
// reports, so that a rotation is seen by the agent's next read, and records the
// order of every change.
type stubManager struct {
	mu     sync.Mutex
	r      *stubReader
	pre    escrow.Preconditions
	preErr error
	vol    *escrow.VolumeInfo
	volErr error
	events []string
	fail   map[string]error
}

func (m *stubManager) ev(e string) { m.events = append(m.events, e) }

func (m *stubManager) Preconditions(context.Context) (escrow.Preconditions, error) {
	return m.pre, m.preErr
}

func (m *stubManager) Volume(context.Context, string) (*escrow.VolumeInfo, error) {
	return m.vol, m.volErr
}

func (m *stubManager) AddRecoveryPassword(_ context.Context, vol string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail["add"]; err != nil {
		return "", err
	}
	m.ev("add")
	m.r.mu.Lock()
	defer m.r.mu.Unlock()
	if len(m.r.volumes) > 0 {
		m.r.volumes[0].Protectors = append(m.r.volumes[0].Protectors, newProt)
	}
	m.r.passwords[vol+"|"+newProt] = newPass
	return newProt, nil
}

func (m *stubManager) DeleteProtector(_ context.Context, _, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail["delete:"+id]; err != nil {
		return err
	}
	m.ev("delete:" + id)
	m.r.mu.Lock()
	defer m.r.mu.Unlock()
	if len(m.r.volumes) > 0 {
		m.r.volumes[0].Protectors = slices.DeleteFunc(m.r.volumes[0].Protectors, func(p string) bool { return p == id })
	}
	return nil
}

func (m *stubManager) AddTPMProtector(context.Context, string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail["tpm"]; err != nil {
		return err
	}
	m.ev("tpm")
	return nil
}

func (m *stubManager) StartEncryption(_ context.Context, _ string, usedOnly bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail["encrypt"]; err != nil {
		return err
	}
	if usedOnly {
		m.ev("encrypt:used")
	} else {
		m.ev("encrypt:full")
	}
	return nil
}

func (m *stubManager) joined() string { return strings.Join(m.events, ",") }

// managerFx is an agent with a key, a manager over an unencrypted volume, and a
// server that says the password verified.
func managerFx(t *testing.T) (*fx, *stubManager) {
	f := newFx(t)
	f.reader.volumes = []escrow.Volume{{ID: mgrVol, Mount: "C:", Status: "decrypted"}}
	m := &stubManager{
		r:    f.reader,
		pre:  escrow.Preconditions{Computer: computer, TPMReady: true, EditionAllows: true},
		vol:  &escrow.VolumeInfo{ID: mgrVol, Mount: "C:", Status: "decrypted"},
		fail: map[string]error{},
	}
	f.a.Manager = m
	f.server.need = nil
	f.a.Answered(f.signed(1, "key-1", nil))
	return f, m
}

type enableOut struct {
	OK      bool                             `json:"ok"`
	Version int                              `json:"version"`
	Data    agentproto.BitLockerEnableResult `json:"data"`
	Error   struct{ Code, Message string }   `json:"error"`
}

func (f *fx) enable(p agentproto.BitLockerEnableParams) enableOut {
	f.t.Helper()
	line := f.a.EnableBitLocker(context.Background(), p)
	body, ok := strings.CutPrefix(strings.TrimSpace(line), agentproto.NativeResultPrefix)
	if !ok {
		f.t.Fatalf("not a result line: %q", line)
	}
	var out enableOut
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		f.t.Fatal(err)
	}
	if out.Version != agentproto.NativeBitLockerEnableVersion {
		f.t.Fatalf("version %d", out.Version)
	}
	return out
}

var enableP = agentproto.BitLockerEnableParams{Computer: computer, Volume: "C:"}

func TestEnableEscrowsAndVerifiesBeforeItEncrypts(t *testing.T) {
	f, m := managerFx(t)
	out := f.enable(enableP)
	if !out.OK || out.Data.Encryption != "started" || out.Data.Escrow != "verified" || out.Data.Mode != "used_space" {
		t.Fatalf("result: %+v", out)
	}
	if m.joined() != "add,tpm,encrypt:used" {
		t.Fatalf("order: %s", m.joined())
	}
	// The record is for the new protector and holds the password sealed.
	if len(f.server.records) != 1 || f.server.records[0].ProtectorID != newProt {
		t.Fatalf("records: %+v", f.server.records)
	}
	// The protector was reported before the record: the server knows it.
	if len(f.server.reports) == 0 {
		t.Fatal("the new protector was not reported before its record")
	}
	// Nowhere the password could leak.
	all := f.logs.String() + f.server.records[0].Enc + f.server.records[0].Ciphertext + f.server.records[0].Fingerprint
	if strings.Contains(all, newPass) || strings.Contains(all, strings.ReplaceAll(newPass, "-", "")) {
		t.Fatal("the password is in a log or a request")
	}
	// Full encryption on request.
	f2, m2 := managerFx(t)
	if o := f2.enable(agentproto.BitLockerEnableParams{Computer: computer, Volume: "C:", Encryption: "full"}); !o.OK || m2.joined() != "add,tpm,encrypt:full" {
		t.Fatalf("full: %+v %s", o, m2.joined())
	}
}

func TestEnableChangesNothingUntilItsPreconditionsHold(t *testing.T) {
	boom := errors.New("boom")
	cases := map[string]struct {
		mut  func(*stubManager)
		p    agentproto.BitLockerEnableParams
		code string
	}{
		"another computer":    {func(m *stubManager) { m.pre.Computer = "OTHER" }, enableP, "wrong_computer"},
		"the name in a case":  {func(m *stubManager) { m.pre.Computer = "hq-pc" }, enableP, ""},
		"a domain controller": {func(m *stubManager) { m.pre.DomainController = true }, enableP, "domain_controller"},
		"no edition":          {func(m *stubManager) { m.pre.EditionAllows = false }, enableP, "edition_unsupported"},
		"no TPM":              {func(m *stubManager) { m.pre.TPMReady = false }, enableP, "tpm_not_ready"},
		"restart pending":     {func(m *stubManager) { m.pre.RebootPending = true }, enableP, "reboot_pending"},
		"preconditions fail":  {func(m *stubManager) { m.preErr = boom }, enableP, "unsupported"},
		"no such volume":      {func(m *stubManager) { m.vol = nil }, enableP, "volume_not_found"},
		"volume read fails":   {func(m *stubManager) { m.volErr = boom }, enableP, "unsupported"},
		"already encrypted":   {func(m *stubManager) { m.vol.Status = "encrypted" }, enableP, "already_encrypted"},
		"has protectors":      {func(m *stubManager) { m.vol.AnyProtectors = true }, enableP, "already_encrypted"},
		"unknown mode":        {func(*stubManager) {}, agentproto.BitLockerEnableParams{Computer: computer, Volume: "C:", Encryption: "half"}, "bad_params"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f, m := managerFx(t)
			c.mut(m)
			out := f.enable(c.p)
			if c.code == "" {
				if !out.OK {
					t.Fatalf("refused: %+v", out)
				}
				return
			}
			if out.OK || out.Error.Code != c.code {
				t.Fatalf("result %+v, want %s", out, c.code)
			}
			if m.joined() != "" || len(f.server.records) != 0 {
				t.Fatalf("the computer was changed (%s) or a record sent", m.joined())
			}
		})
	}
}

func TestEnableNeedsAnEscrowKeyAndAManager(t *testing.T) {
	f := newFx(t)
	if out := f.enable(enableP); out.OK || out.Error.Code != "unsupported" {
		t.Fatalf("no manager: %+v", out)
	}
	f2, m := managerFx(t)
	f2.now = f2.now.Add(48 * 3600 * 1e9) // the signed key has expired
	if out := f2.enable(enableP); out.OK || out.Error.Code != "escrow_not_ready" || m.joined() != "" {
		t.Fatalf("an expired key: %+v %s", out, m.joined())
	}
	f3 := newFx(t)
	f3.a.Manager = &stubManager{r: f3.reader, fail: map[string]error{}}
	if out := f3.enable(enableP); out.OK || out.Error.Code != "escrow_not_ready" {
		t.Fatalf("no key: %+v", out)
	}
}

func TestEnableStopsAtTheFirstStepThatFails(t *testing.T) {
	boom := errors.New("boom")
	f, m := managerFx(t)
	m.fail["add"] = boom
	if out := f.enable(enableP); out.OK || out.Error.Code != "protector_failed" || m.joined() != "" {
		t.Fatalf("add: %+v %s", out, m.joined())
	}
	// The upload fails: the unescrowed protector is removed, nothing else.
	f, m = managerFx(t)
	f.server.err = boom
	if out := f.enable(enableP); out.OK || out.Error.Code != "escrow_unverified" || m.joined() != "add,delete:"+newProt {
		t.Fatalf("upload: %+v %s", out, m.joined())
	}
	// A stale or conflicting answer: removed, never encrypted.
	for _, st := range []string{agentproto.EscrowStale, agentproto.EscrowConflict} {
		f, m = managerFx(t)
		f.server.answer = agentproto.EscrowAnswer{State: st}
		if out := f.enable(enableP); out.OK || m.joined() != "add,delete:"+newProt {
			t.Fatalf("%s: %+v %s", st, out, m.joined())
		}
	}
	// Pending (the keystore is away): the password stays, so the record it
	// made can still be verified, but nothing is encrypted.
	f, m = managerFx(t)
	f.server.answer = agentproto.EscrowAnswer{State: agentproto.EscrowPending}
	if out := f.enable(enableP); out.OK || out.Error.Code != "escrow_unverified" || m.joined() != "add" {
		t.Fatalf("pending: %+v %s", out, m.joined())
	}
	// The TPM protector and encryption fail after the key is escrowed.
	f, m = managerFx(t)
	m.fail["tpm"] = boom
	if out := f.enable(enableP); out.OK || out.Error.Code != "tpm_protector_failed" || m.joined() != "add" {
		t.Fatalf("tpm: %+v %s", out, m.joined())
	}
	f, m = managerFx(t)
	m.fail["encrypt"] = boom
	if out := f.enable(enableP); out.OK || out.Error.Code != "encrypt_failed" || m.joined() != "add,tpm" {
		t.Fatalf("encrypt: %+v %s", out, m.joined())
	}
	// The password cannot be read back.
	f, m = managerFx(t)
	f.reader.passwords = map[string]string{}
	f.reader.volumes = []escrow.Volume{{ID: mgrVol, Mount: "C:", Status: "decrypted"}}
	m.fail["noop"] = nil
	delete(f.reader.passwords, mgrVol+"|"+newProt)
	// AddRecoveryPassword puts the password in; make the reader forget it.
	f.a.Reader = &forgetful{f.reader}
	if out := f.enable(enableP); out.OK || out.Error.Code != "escrow_unverified" || m.joined() != "add,delete:"+newProt {
		t.Fatalf("read: %+v %s", out, m.joined())
	}
}

// forgetful is a reader that cannot read a recovery password.
type forgetful struct{ *stubReader }

func (forgetful) RecoveryPassword(context.Context, string, string) ([]byte, error) {
	return nil, errors.New("no such protector")
}

// rotationFx is a volume with the old protector P1, which the server says is
// due for rotation.
func rotationFx(t *testing.T) (*fx, *stubManager) {
	f := newFx(t)
	f.reader.volumes = []escrow.Volume{{ID: mgrVol, Mount: "C:", Status: "encrypted", Protectors: []string{"{P1}"}}}
	m := &stubManager{r: f.reader, fail: map[string]error{}}
	f.a.Manager = m
	f.server.need = []agentproto.EscrowNeed{{VolumeID: mgrVol, Rotating: "{P1}"}}
	f.server.answer = agentproto.EscrowAnswer{State: agentproto.EscrowVerified}
	f.a.Answered(f.signed(1, "key-1", nil))
	return f, m
}

func TestRotationRemovesTheOldProtectorOnlyOnceTheNewOneIsVerified(t *testing.T) {
	f, m := rotationFx(t)
	f.a.Sync(context.Background())
	if m.joined() != "add,delete:{P1}" {
		t.Fatalf("order: %s", m.joined())
	}
	if len(f.server.records) != 1 || f.server.records[0].ProtectorID != newProt {
		t.Fatalf("records: %+v", f.server.records)
	}
	if strings.Contains(f.logs.String(), newPass) || strings.Contains(f.logs.String(), "123456-234567") {
		t.Fatal("a password is in the log")
	}
}

func TestRotationThatDoesNotVerifyKeepsTheOldProtector(t *testing.T) {
	for _, st := range []string{agentproto.EscrowStale, agentproto.EscrowConflict} {
		f, m := rotationFx(t)
		f.server.answer = agentproto.EscrowAnswer{State: st}
		f.a.Sync(context.Background())
		if m.joined() != "add,delete:"+newProt {
			t.Fatalf("%s: %s (the new one goes, the old one stays)", st, m.joined())
		}
	}
	f, m := rotationFx(t)
	f.server.err = errors.New("network")
	f.a.Sync(context.Background())
	if m.joined() != "add,delete:"+newProt {
		t.Fatalf("a failed upload: %s", m.joined())
	}
	// Pending: both stay; the server names the old one for removal later.
	f, m = rotationFx(t)
	f.server.answer = agentproto.EscrowAnswer{State: agentproto.EscrowPending}
	f.a.Sync(context.Background())
	if m.joined() != "add" {
		t.Fatalf("pending: %s", m.joined())
	}
	// A failed add leaves everything as it was; a protector already gone is
	// nothing to rotate.
	f, m = rotationFx(t)
	m.fail["add"] = errors.New("boom")
	f.a.Sync(context.Background())
	if m.joined() != "" {
		t.Fatalf("failed add: %s", m.joined())
	}
	f, m = rotationFx(t)
	f.server.need = []agentproto.EscrowNeed{{VolumeID: mgrVol, Rotating: "{GONE}"}}
	f.a.Sync(context.Background())
	if m.joined() != "" {
		t.Fatalf("a protector that is not there: %s", m.joined())
	}
	// No manager: the need is ignored.
	f, _ = rotationFx(t)
	f.a.Manager = nil
	f.a.Sync(context.Background())
	if len(f.server.records) != 0 {
		t.Fatal("a rotation without a manager sent a record")
	}
}

func TestRemovalFollowsTheServersVerifiedSuccessor(t *testing.T) {
	f, m := rotationFx(t)
	f.reader.volumes[0].Protectors = []string{"{P1}", "{P2}"}
	f.server.need = []agentproto.EscrowNeed{{VolumeID: mgrVol, Remove: []string{"{P1}", "{P2}", "{GONE}"}, Successor: "{P2}"}}
	f.a.Sync(context.Background())
	// Never the successor, and only what is there.
	if m.joined() != "delete:{P1}" {
		t.Fatalf("removal: %s", m.joined())
	}
	// A successor that is not on the volume removes nothing.
	f, m = rotationFx(t)
	f.server.need = []agentproto.EscrowNeed{{VolumeID: mgrVol, Remove: []string{"{P1}"}, Successor: "{NOPE}"}}
	f.a.Sync(context.Background())
	if m.joined() != "" {
		t.Fatalf("no successor: %s", m.joined())
	}
	// An invalid need is skipped.
	f, m = rotationFx(t)
	f.server.need = []agentproto.EscrowNeed{{VolumeID: mgrVol, Remove: []string{"{P1}"}}}
	f.a.Sync(context.Background())
	if m.joined() != "" {
		t.Fatalf("a removal with no successor: %s", m.joined())
	}
}

func TestWatchedRotationsAreReportedEveryReadInterval(t *testing.T) {
	f, _ := rotationFx(t)
	f.server.need = nil
	f.server.watch = true
	f.a.Sync(context.Background())
	n := len(f.server.reports)
	f.now = f.now.Add(11 * 60 * 1e9) // a read interval, not an hour
	f.a.Sync(context.Background())
	if len(f.server.reports) != n+1 {
		t.Fatalf("a watched rotation was reported %d times after %d", len(f.server.reports), n)
	}
}

func TestLUKSRemovalFollowsTheServersVerifiedSuccessor(t *testing.T) {
	old, succ := "0a0a0a0a-0000-4000-8000-0000000000aa", "0a0a0a0a-0000-4000-8000-0000000000bb"
	f, l := luksFx(t)
	l.volumes[0].Slots = []escrow.LUKSSlot{{TokenID: old, Hash: strings.Repeat("ab", 32)}, {TokenID: succ, Hash: strings.Repeat("cd", 32)}}
	f.server.need = []agentproto.EscrowNeed{{VolumeID: luksVol, Remove: []string{old, succ}, Successor: succ}}
	f.a.Answered(f.signed(1, "key-1", nil))
	f.a.Sync(context.Background())
	if len(l.removed) != 1 || l.removed[0] != old {
		t.Fatalf("removed %v", l.removed)
	}
	f2, l2 := luksFx(t)
	l2.volumes[0].Slots = []escrow.LUKSSlot{{TokenID: old, Hash: strings.Repeat("ab", 32)}}
	f2.server.need = []agentproto.EscrowNeed{{VolumeID: luksVol, Remove: []string{old}, Successor: succ}}
	f2.a.Answered(f2.signed(1, "key-1", nil))
	f2.a.Sync(context.Background())
	if len(l2.removed) != 0 {
		t.Fatalf("a missing successor removed %v", l2.removed)
	}
}

func TestSystemManagerOffWindows(t *testing.T) {
	var m escrow.SystemManager
	if _, err := m.Preconditions(context.Background()); err == nil {
		t.Skip("Windows")
	}
	if _, err := m.Volume(context.Background(), "C:"); !errors.Is(err, escrow.ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := m.AddRecoveryPassword(context.Background(), "v"); !errors.Is(err, escrow.ErrUnsupported) {
		t.Fatal(err)
	}
	for _, err := range []error{m.DeleteProtector(context.Background(), "v", "p"), m.AddTPMProtector(context.Background(), "v"), m.StartEncryption(context.Background(), "v", true)} {
		if !errors.Is(err, escrow.ErrUnsupported) {
			t.Fatal(err)
		}
	}
}
