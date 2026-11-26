package defender

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// fakeDefender is Defender's lists in memory: what the real one keeps.
type fakeDefender struct {
	prefs   Prefs
	readErr error
	addErr  map[string]error // by kind
	swallow bool             // accepts an add and lists nothing
	adds    []string
	removes []string
}

func (f *fakeDefender) Method() string { return "powershell" }
func (f *fakeDefender) Read(context.Context) (Prefs, error) {
	if f.readErr != nil {
		return Prefs{}, f.readErr
	}
	p := f.prefs
	p.Lists = map[string][]string{}
	for k, v := range f.prefs.Lists {
		p.Lists[k] = append([]string{}, v...)
	}
	return p, nil
}
func (f *fakeDefender) Add(_ context.Context, kind, path string) error {
	if err := f.addErr[kind]; err != nil {
		return err
	}
	f.adds = append(f.adds, kind+" "+path)
	if !f.swallow {
		f.prefs.Lists[kind] = append(f.prefs.Lists[kind], path)
	}
	return nil
}
func (f *fakeDefender) Remove(_ context.Context, kind, path string) error {
	f.removes = append(f.removes, kind+" "+path)
	var keep []string
	for _, e := range f.prefs.Lists[kind] {
		if !same(e, path) {
			keep = append(keep, e)
		}
	}
	f.prefs.Lists[kind] = keep
	return nil
}

// fakeSystem answers for folders by name.
type fakeSystem struct{ lockErr, verifyErr map[string]error }

func (s fakeSystem) Lock(d string) error   { return s.lockErr[d] }
func (s fakeSystem) Verify(d string) error { return s.verifyErr[d] }

func active() Prefs {
	return Prefs{Lists: map[string][]string{}, RunningMode: "Normal", AntivirusOn: true, ServiceOn: true, RealTimeOn: true, CFAOn: true, ASRRules: 2}
}

const (
	progData  = `C:\ProgramData\EasyRMM\Agent`
	progAgent = `C:\Program Files\EasyRMM\Agent`
	progMesh  = `C:\Program Files\EasyRMM\MeshAgent`
	exeAgent  = progAgent + `\easyrmm-agent.exe`
	exeMesh   = progMesh + `\meshagent.exe`
)

func newManager(t *testing.T, f *fakeDefender, s fakeSystem) *Manager {
	t.Helper()
	return &Manager{
		Backend: f, System: s, Folders: []string{progData, progAgent, progMesh}, Programs: []string{exeAgent, exeMesh},
		RecordFile: filepath.Join(t.TempDir(), RecordFile), Version: "v1", Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func kindState(r *agentproto.DefenderReport, k string) agentproto.DefenderKind {
	for _, x := range r.Kinds {
		if x.Kind == k {
			return x
		}
	}
	return agentproto.DefenderKind{}
}

func TestReconcileAddsAllFourKindsAndRecordsThem(t *testing.T) {
	f := &fakeDefender{prefs: active()}
	m := newManager(t, f, fakeSystem{})
	r := m.Reconcile(context.Background())
	if r.State != agentproto.DefenderEffective {
		t.Fatalf("state = %s (%s)", r.State, r.Reason)
	}
	// Three folders as path and ASR, two programs as process and CFA.
	if len(f.adds) != 10 {
		t.Fatalf("adds = %v", f.adds)
	}
	for _, bad := range f.adds {
		if strings.Contains(strings.ToLower(bad), "powershell") || strings.Contains(bad, "%TEMP%") || strings.Contains(bad, "extension") {
			t.Fatalf("a forbidden exclusion: %s", bad)
		}
	}
	rec, found, err := LoadRecord(m.RecordFile)
	if err != nil || !found || len(rec.Entries) != 10 {
		t.Fatalf("record = %+v %v %v", rec, found, err)
	}
	if err := r.Check(); err != nil {
		t.Fatal(err)
	}
	for _, f := range r.Folders {
		if !f.Listed || !f.Ours {
			t.Fatalf("folder %+v", f)
		}
	}
	if ev := r.Events; len(ev) < 10 {
		t.Fatalf("events = %d", len(ev))
	}
	// A second pass changes nothing.
	f.adds = nil
	if r := m.Reconcile(context.Background()); r.State != agentproto.DefenderEffective || len(f.adds) != 0 {
		t.Fatalf("second pass: %s %v", r.State, f.adds)
	}
}

func TestPreExistingExclusionIsNotOursAndSurvivesUninstall(t *testing.T) {
	f := &fakeDefender{prefs: active()}
	f.prefs.Lists["path"] = []string{strings.ToUpper(progAgent), `D:\ByHand`}
	m := newManager(t, f, fakeSystem{})
	m.Reconcile(context.Background())
	rec, _, _ := LoadRecord(m.RecordFile)
	if rec.Has("path", progAgent) {
		t.Fatal("an administrator's exclusion was recorded as ours")
	}
	left, err := m.Remove(context.Background())
	if err != nil || len(left.Entries) != 0 {
		t.Fatalf("remove: %v %v", left, err)
	}
	if !listed(f.prefs.Lists["path"], `D:\ByHand`) || !listed(f.prefs.Lists["path"], progAgent) {
		t.Fatalf("an exclusion that was not ours was removed: %v", f.prefs.Lists["path"])
	}
	if listed(f.prefs.Lists["path"], progData) || len(f.prefs.Lists["process"]) != 0 {
		t.Fatalf("ours were not removed: %v", f.prefs.Lists)
	}
	if _, err := os.Stat(m.RecordFile); !os.IsNotExist(err) {
		t.Fatal("the record was kept after a complete removal")
	}
}

func TestRemoveRemovesExactlyTheRecord(t *testing.T) {
	f := &fakeDefender{prefs: active()}
	m := newManager(t, f, fakeSystem{})
	m.Reconcile(context.Background())
	f.removes = nil
	if _, err := m.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.removes) != 10 {
		t.Fatalf("removes = %v", f.removes)
	}
}

func TestRemoveWithoutRecordRemovesOnlyTheFixedSetWhereFoldersVerify(t *testing.T) {
	f := &fakeDefender{prefs: active()}
	f.prefs.Lists["path"] = []string{progData, progAgent, progMesh, `D:\ByHand`, `C:\Users`}
	f.prefs.Lists["process"] = []string{exeAgent, `C:\Windows\System32\msiexec.exe`}
	m := newManager(t, f, fakeSystem{verifyErr: map[string]error{progMesh: errors.New("can be changed by BUILTIN\\Users")}})
	if _, err := m.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := f.prefs.Lists["path"]; len(got) != 3 || !listed(got, progMesh) || !listed(got, `D:\ByHand`) || !listed(got, `C:\Users`) {
		t.Fatalf("path list = %v", got)
	}
	if got := f.prefs.Lists["process"]; len(got) != 1 || !listed(got, `C:\Windows\System32\msiexec.exe`) {
		t.Fatalf("process list = %v", got)
	}
}

func TestCorruptRecordFallsBackToTheFixedSet(t *testing.T) {
	f := &fakeDefender{prefs: active()}
	f.prefs.Lists["path"] = []string{progData, `D:\ByHand`}
	m := newManager(t, f, fakeSystem{})
	if err := os.WriteFile(m.RecordFile, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := f.prefs.Lists["path"]; len(got) != 1 || got[0] != `D:\ByHand` {
		t.Fatalf("path list = %v", got)
	}
}

func TestNotLockedAddsNothingAndRemovesItsOwn(t *testing.T) {
	f := &fakeDefender{prefs: active()}
	s := fakeSystem{verifyErr: map[string]error{}}
	m := newManager(t, f, s)
	m.Reconcile(context.Background())
	// The mesh folder becomes writable by Users.
	s.verifyErr[progMesh] = errors.New(progMesh + " can be changed by BUILTIN\\Users")
	f.adds, f.removes = nil, nil
	r := m.Reconcile(context.Background())
	if r.State != agentproto.DefenderNotLocked || !strings.Contains(r.Reason, "BUILTIN") {
		t.Fatalf("state = %s (%s)", r.State, r.Reason)
	}
	if listed(f.prefs.Lists["path"], progMesh) || listed(f.prefs.Lists["asr"], progMesh) || listed(f.prefs.Lists["process"], exeMesh) {
		t.Fatalf("exclusions for the unlocked folder remain: %v", f.prefs.Lists)
	}
	if !listed(f.prefs.Lists["path"], progAgent) {
		t.Fatal("an exclusion of a locked folder went too")
	}
	// A new folder that cannot be locked is never excluded.
	f2 := &fakeDefender{prefs: active()}
	m2 := newManager(t, f2, fakeSystem{lockErr: map[string]error{progData: errors.New("access denied")}})
	r2 := m2.Reconcile(context.Background())
	if r2.State != agentproto.DefenderNotLocked || listed(f2.prefs.Lists["path"], progData) {
		t.Fatalf("a folder that could not be locked was excluded: %s %v", r2.State, f2.prefs.Lists)
	}
	if !strings.Contains(r2.Folders[0].Reason, "could not be locked down") {
		t.Fatalf("folder reason = %q", r2.Folders[0].Reason)
	}
}

func TestStateDecisionTable(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(*fakeDefender)
		state string
		reply string
		added bool
	}{
		{"passive", func(f *fakeDefender) { f.prefs.RunningMode = "Passive" }, agentproto.DefenderNotApplicable, "not the active antivirus", false},
		{"sxs passive", func(f *fakeDefender) { f.prefs.RunningMode = "SxS Passive Mode" }, agentproto.DefenderNotApplicable, "not the active antivirus", false},
		{"edr block", func(f *fakeDefender) { f.prefs.RunningMode = "EDR Block Mode" }, agentproto.DefenderNotApplicable, "", false},
		{"antivirus off", func(f *fakeDefender) { f.prefs.AntivirusOn = false }, agentproto.DefenderNotApplicable, "turned off", false},
		{"realtime off", func(f *fakeDefender) { f.prefs.RealTimeOn = false }, agentproto.DefenderNotApplicable, "real-time", false},
		{"no module", func(f *fakeDefender) { f.prefs = Prefs{Missing: true} }, agentproto.DefenderNotApplicable, "not installed", false},
		{"N/A answer", func(f *fakeDefender) { f.prefs.NA = "N/A: Must be an administrator or have Tamper Protection" }, agentproto.DefenderUnavailable, "N/A", false},
		{"read fails", func(f *fakeDefender) { f.readErr = errors.New("boom") }, agentproto.DefenderUnavailable, "boom", false},
		{"local admin merge off", func(f *fakeDefender) { f.prefs.DisableLocalAdminMerge = true }, agentproto.DefenderNotEffective, "DisableLocalAdminMerge", true},
		{"refused", func(f *fakeDefender) { f.addErr = map[string]error{"path": &Refused{Reason: "Access is denied"}} }, agentproto.DefenderRefused, "Access is denied", true},
		{"tamper", func(f *fakeDefender) {
			f.prefs.TamperProtected = true
			f.addErr = map[string]error{"process": &Refused{Reason: "denied"}}
		}, agentproto.DefenderRefused, "Tamper Protection", true},
		{"accepted but not listed", func(f *fakeDefender) { f.swallow = true }, agentproto.DefenderRefused, "did not list it", true},
		{"other failure", func(f *fakeDefender) { f.addErr = map[string]error{"asr": errors.New("both failed")} }, agentproto.DefenderUnavailable, "both failed", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeDefender{prefs: active()}
			c.edit(f)
			m := newManager(t, f, fakeSystem{})
			r := m.Reconcile(context.Background())
			if r.State != c.state || !strings.Contains(r.Reason, c.reply) {
				t.Fatalf("state = %s (%s), want %s (%s)", r.State, r.Reason, c.state, c.reply)
			}
			if err := r.Check(); err != nil {
				t.Fatal(err)
			}
			if c.state == agentproto.DefenderNotApplicable || c.state == agentproto.DefenderUnavailable && !c.added {
				if len(f.adds) != 0 {
					t.Fatalf("it added %v", f.adds)
				}
			}
			if c.name == "local admin merge off" {
				if rec, _, _ := LoadRecord(m.RecordFile); len(rec.Entries) != 10 {
					t.Fatalf("it still records what it added: %d", len(rec.Entries))
				}
			}
		})
	}
}

func TestNotNeededWhenFeaturesAreOff(t *testing.T) {
	f := &fakeDefender{prefs: active()}
	f.prefs.CFAOn, f.prefs.ASRRules = false, 0
	r := newManager(t, f, fakeSystem{}).Reconcile(context.Background())
	if r.State != agentproto.DefenderEffective {
		t.Fatalf("state = %s (%s)", r.State, r.Reason)
	}
	if kindState(r, "cfa").State != agentproto.DefenderNotNeeded || kindState(r, "asr").State != agentproto.DefenderNotNeeded || kindState(r, "path").State != agentproto.DefenderEffective {
		t.Fatalf("kinds = %+v", r.Kinds)
	}
}

func TestPartialRemovalKeepsWhatFailed(t *testing.T) {
	f := &fakeDefender{prefs: active()}
	m := newManager(t, f, fakeSystem{})
	m.Reconcile(context.Background())
	m.Backend = failingRemove{f, "process"}
	left, err := m.Remove(context.Background())
	if err != nil || len(left.Entries) != 2 {
		t.Fatalf("left = %+v %v", left, err)
	}
	if rec, found, _ := LoadRecord(m.RecordFile); !found || len(rec.Entries) != 2 {
		t.Fatalf("record = %+v", rec)
	}
}

type failingRemove struct {
	*fakeDefender
	kind string
}

func (f failingRemove) Remove(ctx context.Context, kind, path string) error {
	if kind == f.kind {
		return errors.New("denied")
	}
	return f.fakeDefender.Remove(ctx, kind, path)
}

func TestEventsAreTakenOnce(t *testing.T) {
	f := &fakeDefender{prefs: active()}
	m := newManager(t, f, fakeSystem{})
	m.Reconcile(context.Background())
	if ev := m.TakeEvents(); len(ev) != 0 {
		t.Fatalf("a report carries its events once: %d left", len(ev))
	}
	m.RestoreEvents([]agentproto.DefenderEvent{{Kind: "add", Path: "x"}})
	if ev := m.TakeEvents(); len(ev) != 1 {
		t.Fatalf("restored events = %d", len(ev))
	}
}

func TestRecordRoundTripAndCorruption(t *testing.T) {
	file := filepath.Join(t.TempDir(), "r.json")
	if r, found, err := LoadRecord(file); found || err != nil || len(r.Entries) != 0 {
		t.Fatal("a missing record is empty")
	}
	r := Record{}
	r.Put(Entry{Kind: "path", Path: `C:\A`})
	r.Put(Entry{Kind: "path", Path: `c:\a\`})
	if len(r.Entries) != 1 {
		t.Fatal("paths compare case-insensitively")
	}
	if err := r.Save(file); err != nil {
		t.Fatal(err)
	}
	if got, _, err := LoadRecord(file); err != nil || !got.Has("path", `C:\a`) {
		t.Fatalf("%+v %v", got, err)
	}
	_ = os.WriteFile(file, []byte(`{"version":1,"entries":[{"kind":"extension","path":"x"}]}`), 0o600)
	if _, _, err := LoadRecord(file); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v", err)
	}
}
