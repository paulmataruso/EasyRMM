package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/agent/host"
	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// serverKey is a job key of the server's ring.
type serverKey struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	gen  int64
}

func newServerKey(gen int64) serverKey {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return serverKey{pub: pub, priv: priv, gen: gen}
}

type recorded struct{ kind, id, signer string }

type keyFixture struct {
	t       *testing.T
	store   state.Store
	cfg     *state.Config
	ks      *KeyStore
	devPub  ed25519.PublicKey
	install string
	now     time.Time
	log     []recorded
	k1, k2  serverKey
	stmtN   int
}

// newKeyFixture is an agent that trusts k1 (generation 1) alone, as an agent
// moved from before this ADR does after its first answer.
func newKeyFixture(t *testing.T) *keyFixture {
	t.Helper()
	store, _, err := state.Open(host.Paths{Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	devPub, devPriv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	f := &keyFixture{t: t, store: store, devPub: devPub, install: agentproto.InstallID(devPub), now: now,
		k1: newServerKey(1), k2: newServerKey(now.UnixMilli())}
	f.cfg = &state.Config{Server: "https://rmm.example.com", DeviceID: "dev-1"}
	f.cfg.PinFirstKey(agentproto.EncodeKey(f.k1.pub), 1)
	if err := store.Save(f.cfg, devPriv); err != nil {
		t.Fatal(err)
	}
	f.ks = f.build()
	return f
}

func (f *keyFixture) build() *KeyStore {
	return &KeyStore{DeviceID: "dev-1", Install: f.install, Config: f.cfg, Store: f.store,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return f.now },
		Record: func(kind, id, signer string) { f.log = append(f.log, recorded{kind, id, signer}) }}
}

// restart makes a store over the configuration as the file holds it now.
func (f *keyFixture) restart() {
	f.t.Helper()
	cfg, _, err := loadConfig(f.store)
	if err != nil {
		f.t.Fatal(err)
	}
	f.cfg = cfg
	f.ks = f.build()
}

// loadConfig reads agent.json the way a restart does: Load needs the device
// key, so write one first.
func loadConfig(s state.Store) (*state.Config, ed25519.PrivateKey, error) {
	return s.Load()
}

func (f *keyFixture) stmt(k serverKey, gen int64, mutate func(*agentproto.KeyStatement)) agentproto.KeyStatement {
	f.stmtN++
	p := agentproto.KeyStatement{V: agentproto.KeyStatementVersion, ID: "s-" + string(rune('a'+f.stmtN)), DeviceID: "dev-1", Install: f.install,
		Key: agentproto.EncodeKey(k.pub), Generation: gen, IssuedAt: f.now, ExpiresAt: f.now.Add(agentproto.KeyStatementValid)}
	if mutate != nil {
		mutate(&p)
	}
	return p
}

func (f *keyFixture) handover(signer, introduced serverKey, mutate func(*agentproto.KeyStatement)) *agentproto.SignedKeyStatement {
	f.t.Helper()
	p := f.stmt(introduced, introduced.gen, mutate)
	s, err := agentproto.SignHandover(signer.priv, p)
	if err != nil {
		f.t.Fatal(err)
	}
	return &s
}

func (f *keyFixture) cutover(k serverKey, mutate func(*agentproto.KeyStatement)) *agentproto.SignedKeyStatement {
	f.t.Helper()
	p := f.stmt(k, k.gen, mutate)
	s, err := agentproto.SignCutover(k.priv, p)
	if err != nil {
		f.t.Fatal(err)
	}
	return &s
}

func (f *keyFixture) trusts() []int64 {
	var out []int64
	for _, k := range f.ks.Report() {
		out = append(out, k.Generation)
	}
	return out
}

func (f *keyFixture) refusal() string {
	if r := f.ks.Refusal(); r != nil {
		return r.Statement + ": " + r.Reason
	}
	return ""
}

func TestHandoverThenCutoverMovesTheAgent(t *testing.T) {
	f := newKeyFixture(t)
	f.ks.Answered(2, f.handover(f.k1, f.k2, nil), nil)
	if got := f.trusts(); !reflect.DeepEqual(got, []int64{1, f.k2.gen}) {
		t.Fatalf("after the hand-over: %v", got)
	}
	if f.ks.Refusal() != nil {
		t.Fatalf("refusal %v", f.refusal())
	}
	// Both keys verify instructions; jobKey keeps the oldest for older builds.
	if keys := f.ks.Keys(); len(keys) != 2 || !keys.Contains(f.k1.pub) || !keys.Contains(f.k2.pub) {
		t.Fatalf("keys %v", keys)
	}
	if f.cfg.JobKey != agentproto.EncodeKey(f.k1.pub) {
		t.Errorf("jobKey is not the oldest")
	}
	if f.ks.InTransition() {
		t.Error("a transition after a hand-over alone")
	}
	f.ks.Answered(2, nil, f.cutover(f.k2, nil))
	if got := f.trusts(); !reflect.DeepEqual(got, []int64{f.k2.gen}) {
		t.Fatalf("after the cut-over: %v", got)
	}
	if keys := f.ks.Keys(); keys.Contains(f.k1.pub) {
		t.Error("the old key is still trusted")
	}
	if f.cfg.JobKey != agentproto.EncodeKey(f.k2.pub) {
		t.Error("jobKey does not follow the oldest")
	}
	if d := f.ks.Dropped(); len(d) != 1 || !d.Contains(f.k1.pub) {
		t.Errorf("dropped %v", d)
	}
	// The declared transition: from the cut-over until ten minutes after,
	// and across a restart.
	if !f.ks.InTransition() {
		t.Fatal("no transition after the cut-over")
	}
	f.restart()
	if !f.ks.InTransition() {
		t.Error("the transition did not survive a restart")
	}
	f.now = f.now.Add(TransitionLength - time.Second)
	if !f.ks.InTransition() {
		t.Error("the transition ended early")
	}
	f.now = f.now.Add(2 * time.Second)
	if f.ks.InTransition() {
		t.Error("the transition did not end")
	}
	// Both statements were logged with the key that signed them.
	want := []recorded{
		{agentproto.InstructionHandover, agentproto.Fingerprint(f.k2.pub), agentproto.Fingerprint(f.k1.pub)},
		{agentproto.InstructionCutover, agentproto.Fingerprint(f.k2.pub), agentproto.Fingerprint(f.k2.pub)},
	}
	if !reflect.DeepEqual(f.log, want) {
		t.Errorf("log %v", f.log)
	}
}

func TestHandoverRefusals(t *testing.T) {
	stranger := newServerKey(5)
	tests := map[string]struct {
		build  func(f *keyFixture) *agentproto.SignedKeyStatement
		reason string
	}{
		"a signer the agent does not trust": {func(f *keyFixture) *agentproto.SignedKeyStatement { return f.handover(stranger, f.k2, nil) }, "signature"},
		"another device": {func(f *keyFixture) *agentproto.SignedKeyStatement {
			return f.handover(f.k1, f.k2, func(p *agentproto.KeyStatement) { p.DeviceID = "dev-2" })
		}, "another device"},
		"another install": {func(f *keyFixture) *agentproto.SignedKeyStatement {
			return f.handover(f.k1, f.k2, func(p *agentproto.KeyStatement) { p.Install = strings.Repeat("a", 64) })
		}, "another install"},
		"expired": {func(f *keyFixture) *agentproto.SignedKeyStatement {
			return f.handover(f.k1, f.k2, func(p *agentproto.KeyStatement) {
				p.IssuedAt, p.ExpiresAt = f.now.Add(-time.Hour), f.now.Add(-50*time.Minute)
			})
		}, "expired"},
		"a generation not above": {func(f *keyFixture) *agentproto.SignedKeyStatement {
			low := newServerKey(1)
			return f.handover(f.k1, low, nil)
		}, "not above"},
		"a generation more than five minutes ahead": {func(f *keyFixture) *agentproto.SignedKeyStatement {
			far := newServerKey(f.now.Add(agentproto.MaxSkew + time.Minute).UnixMilli())
			return f.handover(f.k1, far, nil)
		}, "ahead"},
		"an unknown field": {func(f *keyFixture) *agentproto.SignedKeyStatement {
			p := f.stmt(f.k2, f.k2.gen, nil)
			b, _ := json.Marshal(p)
			b = []byte(strings.Replace(string(b), `"v":1`, `"v":1,"extra":1`, 1))
			sig := ed25519.Sign(f.k1.priv, append([]byte("EASYRMM-JOB-KEY-HANDOVER-V1\n"), b...))
			return &agentproto.SignedKeyStatement{Payload: base64.StdEncoding.EncodeToString(b), Signature: base64.StdEncoding.EncodeToString(sig)}
		}, "malformed"},
		"oversize": {func(f *keyFixture) *agentproto.SignedKeyStatement {
			return &agentproto.SignedKeyStatement{Payload: strings.Repeat("A", agentproto.MaxKeyStatementPayload+4), Signature: "x"}
		}, ""},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			f := newKeyFixture(t)
			f.ks.Answered(2, tc.build(f), nil)
			if got := f.trusts(); !reflect.DeepEqual(got, []int64{1}) {
				t.Fatalf("the agent now trusts %v", got)
			}
			if tc.reason != "" && !strings.Contains(f.refusal(), tc.reason) {
				t.Errorf("refusal %q does not say %q", f.refusal(), tc.reason)
			}
			if len(f.log) != 0 {
				t.Errorf("a refused statement was logged: %v", f.log)
			}
		})
	}
}

func TestHandoverReplayAndOlderStatements(t *testing.T) {
	f := newKeyFixture(t)
	k3 := newServerKey(f.k2.gen + 1000)
	first := f.handover(f.k1, f.k2, nil)
	f.ks.Answered(2, first, nil)
	// The same statement again changes nothing and is no error.
	f.ks.Answered(2, first, nil)
	if f.ks.Refusal() != nil || len(f.trusts()) != 2 || len(f.log) != 1 {
		t.Fatalf("a repeat: %v %v %v", f.refusal(), f.trusts(), f.log)
	}
	// Another statement for the same key at the same generation (a second
	// server) is harmless too.
	f.ks.Answered(2, f.handover(f.k1, f.k2, nil), nil)
	if f.ks.Refusal() != nil || len(f.trusts()) != 2 {
		t.Fatalf("a second server's: %v %v", f.refusal(), f.trusts())
	}
	// A newer key is handed over, then an older statement for another key
	// issued before it is a replay.
	issuedAt := func(at time.Time) func(*agentproto.KeyStatement) {
		return func(p *agentproto.KeyStatement) { p.IssuedAt, p.ExpiresAt = at, at.Add(agentproto.KeyStatementValid) }
	}
	f.now = f.now.Add(time.Minute)
	newer := f.handover(f.k2, k3, issuedAt(f.now.Add(-30*time.Second)))
	f.ks.Answered(2, newer, nil)
	if len(f.trusts()) != 3 {
		t.Fatalf("the newer: %v %v", f.trusts(), f.refusal())
	}
	k4 := newServerKey(k3.gen + 1000)
	older := f.handover(f.k2, k4, issuedAt(f.now.Add(-time.Minute)))
	f.ks.Answered(2, older, nil)
	if !strings.Contains(f.refusal(), "issued before") || len(f.trusts()) != 3 {
		t.Fatalf("an older statement: %q %v", f.refusal(), f.trusts())
	}
	// A replay survives a restart: the log is on disk.
	f.restart()
	f.ks.Answered(2, older, nil)
	if !strings.Contains(f.refusal(), "issued before") {
		t.Errorf("after a restart: %q", f.refusal())
	}
}

func TestHandoverOfADroppedKeyIsRefused(t *testing.T) {
	f := newKeyFixture(t)
	f.ks.Answered(2, f.handover(f.k1, f.k2, nil), nil)
	f.ks.Answered(2, nil, f.cutover(f.k2, nil))
	// The old key signs a hand-over of itself again: its generation is not above.
	f.now = f.now.Add(time.Minute)
	f.ks.Answered(2, f.handover(f.k2, f.k1, nil), nil)
	if f.refusal() == "" || f.ks.Keys().Contains(f.k1.pub) {
		t.Fatalf("a dropped key was trusted again: %q", f.refusal())
	}
}

func TestAtMostFourKeysAndThreeWithAKeyTheServerNeverHeld(t *testing.T) {
	f := newKeyFixture(t)
	gen := f.k2.gen
	var keys []serverKey
	signer := f.k1
	for i := 0; i < 3; i++ {
		k := newServerKey(gen + int64(i)*1000)
		keys = append(keys, k)
		f.now = f.now.Add(time.Second)
		f.ks.Answered(2, f.handover(signer, k, nil), nil)
		signer = k
	}
	if len(f.trusts()) != 4 || f.ks.Refusal() != nil {
		t.Fatalf("four keys: %v %q", f.trusts(), f.refusal())
	}
	// A fifth is refused.
	f.now = f.now.Add(time.Second)
	f.ks.Answered(2, f.handover(signer, newServerKey(gen+9000), nil), nil)
	if len(f.trusts()) != 4 || !strings.Contains(f.refusal(), "more than 4") {
		t.Fatalf("a fifth key: %v %q", f.trusts(), f.refusal())
	}
	// A cut-over to the newest leaves one key; one that is not the newest is refused.
	f.now = f.now.Add(time.Second)
	f.ks.Answered(2, nil, f.cutover(keys[0], nil))
	if len(f.trusts()) != 4 || !strings.Contains(f.refusal(), "not the newest") {
		t.Fatalf("a cut-over to a key that is not the newest: %v %q", f.trusts(), f.refusal())
	}
	f.ks.Answered(2, nil, f.cutover(keys[2], nil))
	if len(f.trusts()) != 1 || len(f.ks.Dropped()) != 3 {
		t.Fatalf("after the cut-over: %v, dropped %d", f.trusts(), len(f.ks.Dropped()))
	}
}

func TestThreeKeysAfterAHandoverToADeviceThatTrustsAnUnknownKey(t *testing.T) {
	// The agent trusts the key the server holds (k1) and one it never held
	// (unknown, newer); the hand-over is signed by k1, the target is above
	// the unknown key's generation, and the cut-over drops the unknown one.
	f := newKeyFixture(t)
	unknown := newServerKey(f.now.UnixMilli() - 1000)
	f.ks.Answered(2, f.handover(f.k1, unknown, nil), nil)
	if len(f.trusts()) != 2 {
		t.Fatalf("setup: %v %q", f.trusts(), f.refusal())
	}
	target := newServerKey(f.now.UnixMilli())
	f.now = f.now.Add(time.Second)
	f.ks.Answered(2, f.handover(f.k1, target, nil), nil)
	if len(f.trusts()) != 3 {
		t.Fatalf("three keys: %v %q", f.trusts(), f.refusal())
	}
	f.ks.Answered(2, nil, f.cutover(target, nil))
	if got := f.trusts(); len(got) != 1 || got[0] != target.gen {
		t.Fatalf("one key: %v", got)
	}
}

func TestAHandoverAheadOfTheClockIsAcceptedOnceTheClockReachesIt(t *testing.T) {
	f := newKeyFixture(t)
	ahead := newServerKey(f.now.Add(agentproto.MaxSkew + 2*time.Minute).UnixMilli())
	f.ks.Answered(2, f.handover(f.k1, ahead, nil), nil)
	if len(f.trusts()) != 1 || !strings.Contains(f.refusal(), "ahead") {
		t.Fatalf("ahead: %v %q", f.trusts(), f.refusal())
	}
	f.now = f.now.Add(3 * time.Minute)
	f.ks.Answered(2, f.handover(f.k1, ahead, nil), nil)
	if len(f.trusts()) != 2 || f.ks.Refusal() != nil {
		t.Fatalf("offered again: %v %q", f.trusts(), f.refusal())
	}
}

func TestCutoverRules(t *testing.T) {
	f := newKeyFixture(t)
	// A cut-over to the only key it trusts changes nothing.
	f.ks.Answered(2, nil, f.cutover(f.k1, nil))
	if len(f.trusts()) != 1 || f.ks.Refusal() != nil || f.ks.InTransition() || len(f.log) != 0 {
		t.Fatalf("to the only key: %v %q %v", f.trusts(), f.refusal(), f.log)
	}
	// A cut-over to a key it does not trust is refused.
	f.ks.Answered(2, nil, f.cutover(f.k2, nil))
	if !strings.Contains(f.refusal(), "signature") || len(f.trusts()) != 1 {
		t.Fatalf("an untrusted key: %q", f.refusal())
	}
	// A cut-over signed by the key that goes (naming the new one) does not verify.
	f.ks.Answered(2, f.handover(f.k1, f.k2, nil), nil)
	p := f.stmt(f.k2, f.k2.gen, nil)
	b, _ := json.Marshal(p)
	sig := ed25519.Sign(f.k1.priv, append([]byte("EASYRMM-JOB-KEY-CUTOVER-V1\n"), b...))
	forged := &agentproto.SignedKeyStatement{Payload: base64.StdEncoding.EncodeToString(b), Signature: base64.StdEncoding.EncodeToString(sig)}
	f.ks.Answered(2, nil, forged)
	if len(f.trusts()) != 2 || !strings.Contains(f.refusal(), "signature") {
		t.Fatalf("a forged cut-over: %v %q", f.trusts(), f.refusal())
	}
	// The same cut-over received twice: once.
	good := f.cutover(f.k2, nil)
	f.ks.Answered(2, nil, good)
	f.ks.Answered(2, nil, good)
	if len(f.trusts()) != 1 || f.ks.Refusal() != nil {
		t.Fatalf("twice: %v %q", f.trusts(), f.refusal())
	}
}

func TestStatementsAreRefusedFromAServerBelowLevelTwoAndRefusalsClear(t *testing.T) {
	f := newKeyFixture(t)
	f.ks.Answered(1, f.handover(f.k1, f.k2, nil), nil)
	if len(f.trusts()) != 1 {
		t.Fatal("a level 1 server moved the agent")
	}
	f.ks.Answered(2, f.handover(newServerKey(9), f.k2, nil), nil)
	if f.ks.Refusal() == nil {
		t.Fatal("no refusal")
	}
	// The refusal is reported until an answer carries no statement.
	f.ks.Answered(2, nil, nil)
	if f.ks.Refusal() != nil {
		t.Error("the refusal was not cleared")
	}
}

func TestKeyWithoutAGenerationAndTheOldJobKeyField(t *testing.T) {
	f := newKeyFixture(t)
	// agent.json from before this ADR: jobKey alone.
	f.cfg.JobKeys = nil
	f.cfg.JobKey = agentproto.EncodeKey(f.k1.pub)
	f.ks = f.build()
	if r := f.ks.Report(); len(r) != 1 || r[0].Generation != 0 {
		t.Fatalf("report %v", r)
	}
	// The generation is learnt from an answer carrying the same key and one.
	if ok, err := f.ks.Pin(agentproto.EncodeKey(f.k1.pub), 1); !ok || err != nil {
		t.Fatalf("pin: %v %v", ok, err)
	}
	if r := f.ks.Report(); r[0].Generation != 1 {
		t.Fatalf("learnt %v", r)
	}
	if f.cfg.JobKeys[0].Generation != 1 {
		t.Error("not written")
	}
	// A key it does not trust is never followed this way.
	if ok, _ := f.ks.Pin(agentproto.EncodeKey(f.k2.pub), 7); ok || len(f.ks.Keys()) != 1 {
		t.Error("a different key was pinned")
	}
	// jobKeys, when it exists, wins over jobKey on reading.
	f.cfg.JobKeys = []state.JobKey{{Key: agentproto.EncodeKey(f.k2.pub), Generation: 2}}
	f.cfg.JobKey = agentproto.EncodeKey(f.k1.pub)
	if keys := f.ks.Keys(); len(keys) != 1 || !keys.Contains(f.k2.pub) {
		t.Errorf("jobKey was read beside jobKeys: %v", keys)
	}
	// Nothing is pinned until the server sends a key; then first use pins it.
	empty := &KeyStore{DeviceID: "dev-1", Install: f.install, Config: &state.Config{Server: "s", DeviceID: "dev-1"}, Store: f.store}
	if len(empty.Keys()) != 0 {
		t.Fatal("keys from nothing")
	}
	if ok, err := empty.Pin(agentproto.EncodeKey(f.k1.pub), 0); !ok || err != nil || len(empty.Keys()) != 1 {
		t.Fatalf("first use: %v %v", ok, err)
	}
	if _, err := empty.Pin("not a key", 1); err == nil {
		t.Error("a bad key was pinned")
	}
	if ok, err := empty.Pin("", 1); ok || err != nil {
		t.Error("an empty key")
	}
}

func TestReplaceIsTrustKey(t *testing.T) {
	f := newKeyFixture(t)
	f.ks.Answered(2, f.handover(f.k1, f.k2, nil), nil)
	other := newServerKey(0)
	// A lower generation than the agent trusts is refused unless forced.
	if err := f.ks.Replace(5, agentproto.EncodeKey(other.pub), false); !errors.Is(err, ErrLowerGeneration) {
		t.Fatalf("lower: %v", err)
	}
	if len(f.trusts()) != 2 {
		t.Fatal("a refused replacement changed the keys")
	}
	if err := f.ks.Replace(5, agentproto.EncodeKey(other.pub), true); err != nil {
		t.Fatal(err)
	}
	if got := f.trusts(); !reflect.DeepEqual(got, []int64{5}) || f.ks.InTransition() {
		t.Fatalf("forced: %v", got)
	}
	// The server's own key at a higher generation replaces it without --force.
	if err := f.ks.Replace(f.k2.gen, agentproto.EncodeKey(f.k2.pub), false); err != nil {
		t.Fatal(err)
	}
	// Running the same command again changes nothing and is not an error.
	if err := f.ks.Replace(f.k2.gen, agentproto.EncodeKey(f.k2.pub), false); err != nil {
		t.Fatal(err)
	}
	if got := f.trusts(); !reflect.DeepEqual(got, []int64{f.k2.gen}) {
		t.Fatalf("again: %v", got)
	}
	if err := f.ks.Replace(0, agentproto.EncodeKey(f.k2.pub), false); err == nil {
		t.Error("generation 0")
	}
	if err := f.ks.Replace(3, "nope", false); err == nil {
		t.Error("a bad key")
	}
	// The dropped keys are public keys, bounded, never trusted.
	if d := f.ks.Dropped(); len(d) == 0 || d.Contains(f.k2.pub) {
		t.Errorf("dropped %v", d)
	}
	trusted, dropped := View(f.cfg)
	if len(trusted) != 1 || len(dropped) == 0 || trusted[0].Fingerprint != agentproto.Fingerprint(f.k2.pub) {
		t.Errorf("view %v %v", trusted, dropped)
	}
	if got := HeldKeys(f.cfg); len(got) != 1 || !got.Contains(f.k2.pub) {
		t.Errorf("held %v", got)
	}
}

func TestCapsAndCommitFailure(t *testing.T) {
	f := newKeyFixture(t)
	if c := f.ks.Caps(); len(c) != 1 || c[0] != agentproto.CapJobKeys {
		t.Errorf("caps %v", c)
	}
	// A store that cannot write: the keys do not change.
	f.ks.Store = failingStore{}
	f.ks.Answered(2, f.handover(f.k1, f.k2, nil), nil)
	if len(f.trusts()) != 1 || !strings.Contains(f.refusal(), "saving") {
		t.Errorf("a failed write: %v %q", f.trusts(), f.refusal())
	}
}

type failingStore struct{}

func (failingStore) SaveConfig(*state.Config) error { return errors.New("disk full") }
func (failingStore) LoadKeyLog() state.KeyLog       { return state.KeyLog{} }
func (failingStore) SaveKeyLog(state.KeyLog) error  { return nil }

func TestHandoverOfAKeyTrustedAtAnotherGenerationAndOfAKeyWithoutAGeneration(t *testing.T) {
	f := newKeyFixture(t)
	f.ks.Answered(2, f.handover(f.k1, f.k2, nil), nil)
	// The same key at another generation is refused.
	again := f.k2
	again.gen = f.k2.gen + 5
	f.ks.Answered(2, f.handover(f.k1, again, nil), nil)
	if !strings.Contains(f.refusal(), "trusted at generation") {
		t.Fatalf("a key at two generations: %q", f.refusal())
	}
	// A key pinned before generations learns its generation from a hand-over of it.
	g := newKeyFixture(t)
	g.cfg.JobKeys, g.cfg.JobKey = nil, agentproto.EncodeKey(g.k1.pub)
	g.ks = g.build()
	g.ks.Answered(2, g.handover(g.k1, serverKey{pub: g.k1.pub, priv: g.k1.priv, gen: 1}, nil), nil)
	if got := g.trusts(); !reflect.DeepEqual(got, []int64{1}) || g.ks.Refusal() != nil {
		t.Fatalf("learning the generation: %v %q", got, g.refusal())
	}
	// The statement log is bounded.
	h := newKeyFixture(t)
	for i := 0; i < keepHandledKeys+4; i++ {
		h.now = h.now.Add(time.Second)
		h.ks.remember(h.store.LoadKeyLog(), h.stmt(h.k2, h.k2.gen, nil))
	}
	if n := len(h.store.LoadKeyLog().Handled); n != keepHandledKeys {
		t.Errorf("kept %d statement IDs", n)
	}
}

func TestCutoverRefusalsAndKeysWithoutGenerations(t *testing.T) {
	// A cut-over to a key at another generation than the agent holds.
	f := newKeyFixture(t)
	f.ks.Answered(2, f.handover(f.k1, f.k2, nil), nil)
	wrong := f.k2
	wrong.gen = f.k2.gen + 9
	f.ks.Answered(2, nil, f.cutover(wrong, nil))
	if !strings.Contains(f.refusal(), "trusted at generation") || len(f.trusts()) != 2 {
		t.Fatalf("a cut-over at another generation: %q %v", f.refusal(), f.trusts())
	}
	// A cut-over issued before a statement already handled is a replay.
	old := f.cutover(f.k2, func(p *agentproto.KeyStatement) {
		p.IssuedAt, p.ExpiresAt = f.now.Add(-time.Minute), f.now.Add(-time.Minute).Add(agentproto.KeyStatementValid)
	})
	f.now = f.now.Add(time.Second)
	f.ks.Answered(2, nil, old)
	if !strings.Contains(f.refusal(), "issued before") || len(f.trusts()) != 2 {
		t.Fatalf("an older cut-over: %q %v", f.refusal(), f.trusts())
	}
	// A key without a generation, alone: a cut-over names it and teaches the generation.
	g := newKeyFixture(t)
	g.cfg.JobKeys, g.cfg.JobKey = nil, agentproto.EncodeKey(g.k1.pub)
	g.ks = g.build()
	g.ks.Answered(2, nil, g.cutover(serverKey{pub: g.k1.pub, priv: g.k1.priv, gen: 1}, nil))
	if got := g.trusts(); !reflect.DeepEqual(got, []int64{1}) {
		t.Fatalf("learning from a cut-over: %v", got)
	}
	// More than eight dropped keys are not kept.
	h := newKeyFixture(t)
	signer := h.k1
	for i := 0; i < agentproto.MaxDroppedKeys+3; i++ {
		next := newServerKey(h.k2.gen + int64(i)*1000)
		h.now = h.now.Add(time.Second)
		h.ks.Answered(2, h.handover(signer, next, nil), nil)
		h.now = h.now.Add(time.Second)
		h.ks.Answered(2, nil, h.cutover(next, nil))
		signer = next
	}
	if len(h.ks.Dropped()) != agentproto.MaxDroppedKeys || len(h.trusts()) != 1 {
		t.Errorf("dropped %d, trusted %v", len(h.ks.Dropped()), h.trusts())
	}
}

func TestStoreFailuresRefuseTheStatementAndKeepTheKeys(t *testing.T) {
	f := newKeyFixture(t)
	f.ks.Answered(2, f.handover(f.k1, f.k2, nil), nil)
	f.ks.Store = failingStore{}
	f.ks.Answered(2, nil, f.cutover(f.k2, nil))
	if len(f.trusts()) != 2 || !strings.Contains(f.refusal(), "saving") {
		t.Fatalf("a failed cut-over write: %v %q", f.trusts(), f.refusal())
	}
	if err := f.ks.Replace(9, agentproto.EncodeKey(f.k2.pub), true); err == nil {
		t.Error("a failed trust-key write was no error")
	}
	if _, err := f.ks.Pin(agentproto.EncodeKey(f.k1.pub), 7); err != nil && len(f.trusts()) != 2 {
		t.Error("the keys changed")
	}
	// A key pinned before generations learns its generation from a hand-over
	// that the store cannot write.
	g := newKeyFixture(t)
	g.cfg.JobKeys, g.cfg.JobKey = nil, agentproto.EncodeKey(g.k1.pub)
	g.ks = g.build()
	g.ks.Store = failingStore{}
	g.ks.Answered(2, g.handover(g.k1, serverKey{pub: g.k1.pub, priv: g.k1.priv, gen: 1}, nil), nil)
	if !strings.Contains(g.refusal(), "saving") {
		t.Errorf("%q", g.refusal())
	}
	g.ks.Answered(2, nil, g.cutover(serverKey{pub: g.k1.pub, priv: g.k1.priv, gen: 1}, nil))
	if !strings.Contains(g.refusal(), "saving") {
		t.Errorf("%q", g.refusal())
	}
}

// The ADR-0055 trust instruction is logged too: carried out once, by the key
// that signed it.
func TestTrustInstructionIsLogged(t *testing.T) {
	f := newFixture(t)
	if err := os.MkdirAll(f.store.Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	var got []string
	f.agent.Record = func(kind, id, signer string) { got = append(got, kind+"|"+id+"|"+signer) }
	leaf := f.public.leaf(t, testHost)
	f.answer(f.sign(f.payload("m1", chainOf("t", agentproto.TrustTarget, leaf))))
	f.answer(f.sign(f.payload("m1", chainOf("t", agentproto.TrustTarget, leaf)))) // sent again: not again
	want := agentproto.InstructionTrust + "|m1|" + agentproto.Fingerprint(f.pub)
	if len(got) != 1 || got[0] != want {
		t.Errorf("logged %v, want %q", got, want)
	}
}
