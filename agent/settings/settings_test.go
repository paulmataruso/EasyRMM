package settings

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

type memStore struct {
	saved   *state.Settings
	saves   int
	failing bool
}

func (m *memStore) LoadSettings() *state.Settings { return m.saved }
func (m *memStore) SaveSettings(s state.Settings) error {
	if m.failing {
		return errors.New("disk full")
	}
	m.saved, m.saves = &s, m.saves+1
	return nil
}

type fixture struct {
	t     *testing.T
	pub   ed25519.PublicKey
	priv  ed25519.PrivateKey
	store *memStore
	a     *Agent
	rec   []string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	f := &fixture{t: t, pub: pub, priv: priv, store: &memStore{}}
	f.a = f.agent()
	return f
}

// agent is an agent over the fixture's store, as a restart makes one.
func (f *fixture) agent() *Agent {
	return &Agent{DeviceID: "dev-1", Keys: func() agentproto.Keys { return agentproto.Keys{f.pub} }, Store: f.store,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Record: func(kind, id, signer string) { f.rec = append(f.rec, kind+":"+id+":"+signer) }}
}

func (f *fixture) doc(version int64, settings map[string]string) *agentproto.SignedSettings {
	f.t.Helper()
	m := map[string]json.RawMessage{}
	for k, v := range settings {
		m[k] = json.RawMessage(v)
	}
	s, err := agentproto.SignSettings(f.priv, agentproto.SettingsPayload{V: 1, DeviceID: "dev-1", Version: version,
		IssuedAt: time.Unix(1_800_000_000, 0).UTC(), Settings: m})
	if err != nil {
		f.t.Fatal(err)
	}
	return &s
}

// rawSigned signs payload bytes as they are, for documents the server never
// makes.
func rawSigned(priv ed25519.PrivateKey, payload string) *agentproto.SignedSettings {
	sig := ed25519.Sign(priv, append([]byte("EASYRMM-SETTINGS-SIG-V1\n"), payload...))
	return &agentproto.SignedSettings{Payload: base64.StdEncoding.EncodeToString([]byte(payload)), Signature: base64.StdEncoding.EncodeToString(sig)}
}

const hb = "agent.heartbeat_seconds"

func (f *fixture) held() (int64, map[string]string) {
	r := f.a.Report()
	return r.Version, r.Problems
}

func TestCapabilities(t *testing.T) {
	c := newFixture(t).a.Capabilities()
	if !c.Takes(agentproto.CapSettings) || c.Settings[HeartbeatKey] != 1 || len(c.Settings) != 1 {
		t.Errorf("capabilities: %+v", c)
	}
	if c.Check() != nil {
		t.Errorf("the agent's own report fails the server's bounds: %v", c.Check())
	}
}

func TestApplySaveAndReport(t *testing.T) {
	f := newFixture(t)
	if v, p := f.held(); v != 0 || len(p) != 0 {
		t.Fatalf("a new agent holds %d %v", v, p)
	}
	if secs, held := f.a.Interval(60); secs != 60 || held {
		t.Fatalf("no document: the answer's interval, got %d %v", secs, held)
	}
	if !f.a.Answered(3, f.doc(5, map[string]string{hb: "120"})) {
		t.Fatal("an applied document did not ask for a report")
	}
	if v, p := f.held(); v != 5 || len(p) != 0 {
		t.Errorf("after applying: %d %v", v, p)
	}
	if f.store.saves != 1 || f.store.saved.Applied[hb] == nil || string(f.store.saved.Applied[hb]) != "120" {
		t.Errorf("saved: %+v", f.store.saved)
	}
	if secs, held := f.a.Interval(60); secs != 60 || !held {
		t.Errorf("the shorter of 120 and 60: %d %v", secs, held)
	}
	if secs, _ := f.a.Interval(300); secs != 120 {
		t.Errorf("the shorter of 120 and 300: %d", secs)
	}
	if secs, _ := f.a.Interval(0); secs != 120 {
		t.Errorf("an answer without an interval: %d", secs)
	}
	if secs, _ := f.a.Interval(10); secs != 30 {
		t.Errorf("never below 30 seconds: %d", secs)
	}
	if len(f.rec) != 1 || !strings.HasPrefix(f.rec[0], "settings:5:") || len(f.rec[0]) != len("settings:5:")+32 {
		t.Errorf("the instruction log: %v", f.rec)
	}
	// The same document again changes nothing, and asks for nothing.
	if f.a.Answered(3, f.doc(5, map[string]string{hb: "120"})) || f.store.saves != 1 || len(f.rec) != 1 {
		t.Error("the same document again was applied")
	}
	// An answer without a document changes nothing.
	if f.a.Answered(3, nil) {
		t.Error("no document asked for a report")
	}
	// A newer one replaces it.
	if !f.a.Answered(3, f.doc(6, map[string]string{hb: "300"})) {
		t.Fatal("newer not applied")
	}
	if secs, _ := f.a.Interval(300); secs != 300 {
		t.Errorf("after 300: %d", secs)
	}
}

func TestRestartAppliesTheSavedSettingsBeforeAnyHeartbeat(t *testing.T) {
	f := newFixture(t)
	f.a.Answered(3, f.doc(5, map[string]string{hb: "90"}))
	// A restart: a new agent over the same store, no server in reach.
	again := f.agent()
	again.Load()
	if r := again.Report(); r.Version != 5 || len(r.Problems) != 0 {
		t.Fatalf("after a restart: %+v", r)
	}
	if secs, held := again.Interval(60); secs != 60 || !held {
		t.Errorf("interval after a restart: %d %v", secs, held)
	}
	if secs, _ := again.Interval(300); secs != 90 {
		t.Errorf("the saved 90 with a 300 answer: %d", secs)
	}
	// What the restarted agent holds is not applied twice: the same
	// document is a no-op, an older one is refused.
	if again.Answered(3, f.doc(5, map[string]string{hb: "90"})) {
		t.Error("the same document after a restart was applied")
	}
	if !again.Answered(3, f.doc(4, map[string]string{hb: "45"})) {
		t.Error("an older document after a restart was not refused")
	}
	if r := again.Report(); r.Version != 5 || !strings.HasPrefix(r.Problems[agentproto.SettingsDocumentKey], "refused: ") {
		t.Errorf("after refusing: %+v", r)
	}
}

func TestSettingsForAnotherDeviceAreNotApplied(t *testing.T) {
	f := newFixture(t)
	f.a.Answered(3, f.doc(5, map[string]string{hb: "90"}))
	other := f.agent()
	other.DeviceID = "dev-2" // enrolled again as another device
	other.Load()
	if r := other.Report(); r.Version != 0 {
		t.Errorf("settings saved for another device were applied: %+v", r)
	}
	if secs, held := other.Interval(60); secs != 60 || held {
		t.Errorf("not the built-in default: %d %v", secs, held)
	}
	// Damaged, or nothing saved: the built-in defaults.
	f.store.saved.Document.Payload = "%%%"
	damaged := f.agent()
	damaged.Load()
	if r := damaged.Report(); r.Version != 0 {
		t.Errorf("a damaged file was applied: %+v", r)
	}
	f.store.saved = nil
	empty := f.agent()
	empty.Load()
	if r := empty.Report(); r.Version != 0 {
		t.Errorf("nothing saved, yet %+v", r)
	}
	// A saved version outside the range is damage too.
	f.store.saved = &state.Settings{Document: *rawSigned(f.priv, `{"v":1,"deviceId":"dev-1","version":0,"issuedAt":"2027-01-01T00:00:00Z","settings":{}}`)}
	zero := f.agent()
	zero.Load()
	if r := zero.Report(); r.Version != 0 {
		t.Errorf("version 0 applied: %+v", r)
	}
}

func TestRefusalsKeepTheSettingsAndAreReported(t *testing.T) {
	f := newFixture(t)
	f.a.Answered(3, f.doc(5, map[string]string{hb: "90"}))
	saves := f.store.saves
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	wrongDevice, _ := agentproto.SignSettings(f.priv, agentproto.SettingsPayload{V: 1, DeviceID: "dev-2", Version: 9,
		IssuedAt: time.Now(), Settings: map[string]json.RawMessage{hb: json.RawMessage("45")}})
	forged, _ := agentproto.SignSettings(otherPriv, agentproto.SettingsPayload{V: 1, DeviceID: "dev-1", Version: 9,
		IssuedAt: time.Now(), Settings: map[string]json.RawMessage{hb: json.RawMessage("45")}})
	for name, tc := range map[string]struct {
		doc    *agentproto.SignedSettings
		reason string
	}{
		"another device":           {&wrongDevice, "another device"},
		"a lower version":          {f.doc(4, map[string]string{hb: "45"}), "older than"},
		"same version, content":    {f.doc(5, map[string]string{hb: "45"}), "other content"},
		"unknown envelope field":   {rawSigned(f.priv, `{"v":1,"deviceId":"dev-1","version":9,"issuedAt":"2027-01-01T00:00:00Z","settings":{},"extra":1}`), "malformed"},
		"unreported key":           {f.doc(9, map[string]string{hb: "45", "logs.collect": "true"}), "key logs.collect was not reported"},
		"bad signature":            {&forged, "signature"},
		"version out of range":     {f.doc(1<<53, map[string]string{hb: "45"}), "version"},
		"damaged payload":          {&agentproto.SignedSettings{Payload: "%%%", Signature: forged.Signature}, "malformed"},
		"settings null in the doc": {rawSigned(f.priv, `{"v":1,"deviceId":"dev-1","version":9,"issuedAt":"2027-01-01T00:00:00Z","settings":null}`), "malformed"},
	} {
		if !f.a.Answered(3, tc.doc) {
			t.Errorf("%s: no report asked for", name)
		}
		v, p := f.held()
		reason := p[agentproto.SettingsDocumentKey]
		if v != 5 || !strings.HasPrefix(reason, "refused: ") || !strings.Contains(reason, tc.reason) {
			t.Errorf("%s: held %d, reported %q", name, v, reason)
		}
		if len(reason) > agentproto.MaxSettingsReason {
			t.Errorf("%s: reason of %d bytes", name, len(reason))
		}
		if secs, _ := f.a.Interval(300); secs != 90 {
			t.Errorf("%s: the interval moved to %d", name, secs)
		}
	}
	if f.store.saves != saves {
		t.Error("a refused document was saved")
	}
	// A later good document replaces the refusal.
	f.a.Answered(3, f.doc(10, map[string]string{hb: "100"}))
	if v, p := f.held(); v != 10 || len(p) != 0 {
		t.Errorf("after a good document: %d %v", v, p)
	}
	// From a server below level 2, or with no key pinned.
	if !f.a.Answered(1, f.doc(11, map[string]string{hb: "100"})) {
		t.Error("level 1 not refused")
	}
	if _, p := f.held(); !strings.Contains(p[agentproto.SettingsDocumentKey], "level 2") {
		t.Errorf("level 1: %v", p)
	}
	f.a.Keys = func() agentproto.Keys { return nil }
	f.a.Answered(3, f.doc(12, map[string]string{hb: "100"}))
	if v, p := f.held(); v != 10 || !strings.Contains(p[agentproto.SettingsDocumentKey], "signature") {
		t.Errorf("no key pinned: %d %v", v, p)
	}
}

func TestAKeyThatFailsItsSchemaIsInvalidAlone(t *testing.T) {
	f := newFixture(t)
	f.a.Answered(3, f.doc(1, map[string]string{hb: "90"}))
	for name, bad := range map[string]string{"a string": `"fast"`, "a fraction": `61.5`, "null": `null`, "an object": `{"seconds":60}`, "a boolean": `true`, "exponent": `1e2`} {
		f.a.Answered(3, f.doc(f.a.Report().Version+1, map[string]string{hb: bad}))
		v, p := f.held()
		if p[hb] != agentproto.ProblemInvalid {
			t.Errorf("%s: problems %v", name, p)
		}
		if secs, _ := f.a.Interval(300); secs != 90 {
			t.Errorf("%s: the key did not keep its value: %d", name, secs)
		}
		if v < 2 {
			t.Errorf("%s: the rest of the document did not apply (version %d)", name, v)
		}
	}
	// The kept value survives a restart: the saved one holds the value of the
	// earlier document.
	again := f.agent()
	again.Load()
	if secs, _ := again.Interval(300); secs != 90 {
		t.Errorf("after a restart: %d", secs)
	}
	if again.Report().Problems[hb] != agentproto.ProblemInvalid {
		t.Errorf("the problem is not reported again: %v", again.Report().Problems)
	}
	// An invalid value with nothing held takes the built-in default.
	g := newFixture(t)
	g.a.Answered(3, g.doc(1, map[string]string{hb: `"x"`}))
	if secs, held := g.a.Interval(60); held || secs != 60 {
		t.Errorf("invalid with nothing held: %d %v", secs, held)
	}
}

func TestAnIntegerOutOfBoundsIsClamped(t *testing.T) {
	for in, want := range map[string]int{"5": 30, "29": 30, "301": 300, "99999999999": 300, "-4": 30, "30": 30, "300": 300} {
		f := newFixture(t)
		f.a.Answered(3, f.doc(1, map[string]string{hb: in}))
		secs, held := f.a.Interval(300)
		wantProblem := ""
		if in != "30" && in != "300" {
			wantProblem = agentproto.ProblemClamped
		}
		if !held || secs != want || f.a.Report().Problems[hb] != wantProblem {
			t.Errorf("%s: interval %d, problems %v; want %d, %q", in, secs, f.a.Report().Problems, want, wantProblem)
		}
	}
	// Too big for an int64: invalid rather than clamped.
	f := newFixture(t)
	f.a.Answered(3, f.doc(1, map[string]string{hb: "99999999999999999999999"}))
	if f.a.Report().Problems[hb] != agentproto.ProblemInvalid {
		t.Errorf("an enormous integer: %v", f.a.Report().Problems)
	}
}

func TestAKeyTheDocumentOmitsTakesTheDefault(t *testing.T) {
	f := newFixture(t)
	f.a.Answered(3, f.doc(1, map[string]string{hb: "90"}))
	// A later document without the key (a rolled-back server): no value is
	// taken from the earlier document.
	f.a.Answered(3, f.doc(2, nil))
	if secs, held := f.a.Interval(60); held || secs != 60 {
		t.Errorf("an omitted key kept its value: %d %v", secs, held)
	}
	if v, p := f.held(); v != 2 || len(p) != 0 {
		t.Errorf("after the empty document: %d %v", v, p)
	}
}

func TestADocumentThatCannotBeSavedIsNotApplied(t *testing.T) {
	f := newFixture(t)
	f.a.Answered(3, f.doc(1, map[string]string{hb: "90"}))
	f.store.failing = true
	if !f.a.Answered(3, f.doc(2, map[string]string{hb: "45"})) {
		t.Error("no report asked for")
	}
	v, p := f.held()
	if v != 1 || !strings.Contains(p[agentproto.SettingsDocumentKey], "could not save") {
		t.Errorf("held %d, reported %v", v, p)
	}
	if secs, _ := f.a.Interval(300); secs != 90 {
		t.Errorf("the interval moved to %d", secs)
	}
	// The next answer carries the document again, and now it saves.
	f.store.failing = false
	f.a.Answered(3, f.doc(2, map[string]string{hb: "45"}))
	if v, p := f.held(); v != 2 || len(p) != 0 {
		t.Errorf("after the retry: %d %v", v, p)
	}
}

// A build moved back to an older one applies the keys it knows from the saved
// document and takes defaults for the rest.
func TestAnOlderBuildAppliesTheKeysItKnows(t *testing.T) {
	f := newFixture(t)
	f.store.saved = &state.Settings{Document: *f.doc(5, map[string]string{hb: "90", "logs.collect": "true"}),
		Applied: map[string]json.RawMessage{hb: json.RawMessage("90"), "logs.collect": json.RawMessage("true")}}
	f.a.Load()
	if r := f.a.Report(); r.Version != 5 || len(r.Problems) != 0 {
		t.Errorf("an unknown key in a saved document: %+v", r)
	}
	if secs, _ := f.a.Interval(300); secs != 90 {
		t.Errorf("the known key: %d", secs)
	}
	// Judged against this build's schema: a saved 5 is clamped, a saved
	// string is invalid and falls back to what was applied.
	f.store.saved = &state.Settings{Document: *f.doc(6, map[string]string{hb: "5"}), Applied: map[string]json.RawMessage{hb: json.RawMessage("5")}}
	g := f.agent()
	g.Load()
	if secs, _ := g.Interval(300); secs != 30 || g.Report().Problems[hb] != agentproto.ProblemClamped {
		t.Errorf("a saved value outside this build's bounds: %d %v", secs, g.Report().Problems)
	}
}
