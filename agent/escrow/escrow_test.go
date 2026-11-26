package escrow_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/agent/escrow"
	"github.com/paulmataruso/easyrmm/agent/host"
	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/escrowcrypto"
)

const (
	device   = "dev-1"
	org      = "org-1"
	password = "123456-234567-345678-456789-567890-678901-789012-890123"
)

// stubReader stands in for WMI, which Linux does not have.
type stubReader struct {
	mu        sync.Mutex
	volumes   []escrow.Volume
	passwords map[string]string // by volume|protector
	reads     int
	err       error
}

func (s *stubReader) Volumes(context.Context) ([]escrow.Volume, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.volumes, s.err
}

func (s *stubReader) RecoveryPassword(_ context.Context, vol, prot string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	return []byte(s.passwords[vol+"|"+prot]), nil
}

// fakeServer records what the agent sends. It is the network's end; the real
// server's checks are tested against PostgreSQL elsewhere.
type fakeServer struct {
	mu      sync.Mutex
	reports []agentproto.EscrowVolumesReport
	records []agentproto.EscrowRecord
	need    []agentproto.EscrowNeed
	answer  agentproto.EscrowAnswer
	err     error
}

func (f *fakeServer) EscrowVolumes(_ context.Context, r agentproto.EscrowVolumesReport) (agentproto.EscrowVolumesAnswer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports = append(f.reports, r)
	return agentproto.EscrowVolumesAnswer{Need: f.need}, nil
}

func (f *fakeServer) EscrowUpload(_ context.Context, r agentproto.EscrowRecord) (agentproto.EscrowAnswer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return agentproto.EscrowAnswer{}, f.err
	}
	f.records = append(f.records, r)
	return f.answer, nil
}

type fx struct {
	t       *testing.T
	a       *escrow.Agent
	reader  *stubReader
	server  *fakeServer
	store   state.Store
	signPub ed25519.PublicKey
	signKey ed25519.PrivateKey
	orgPriv []byte
	orgPub  []byte
	now     time.Time
	logs    *bytes.Buffer
}

func newFx(t *testing.T) *fx {
	t.Helper()
	store, _, err := state.Open(host.Paths{Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store.Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	f := &fx{t: t, store: store, now: time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC), logs: &bytes.Buffer{}}
	f.signPub, f.signKey, _ = ed25519.GenerateKey(rand.Reader)
	f.orgPriv, f.orgPub, _ = escrowcrypto.GenerateKey()
	f.reader = &stubReader{
		volumes:   []escrow.Volume{{ID: `\\?\Volume{1}\`, Mount: "C:", Status: "encrypted", Protectors: []string{"{P1}"}}},
		passwords: map[string]string{`\\?\Volume{1}\|{P1}`: password},
	}
	f.server = &fakeServer{need: []agentproto.EscrowNeed{{VolumeID: `\\?\Volume{1}\`, ProtectorID: "{P1}"}}, answer: agentproto.EscrowAnswer{State: "verified"}}
	f.a = &escrow.Agent{
		DeviceID: device, Key: func() ed25519.PublicKey { return f.signPub },
		Reader: f.reader, Server: f.server, Store: f.store,
		Log: slog.New(slog.NewTextHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Now: func() time.Time { return f.now },
	}
	return f
}

func (f *fx) signed(version int, keyID string, mutate func(*agentproto.EscrowKeyPayload)) *agentproto.SignedEscrowKey {
	p := agentproto.EscrowKeyPayload{
		V: agentproto.EscrowKeyPayloadVersion, DeviceID: device, OrgID: org, KeyID: keyID, KeyVersion: version,
		PublicKey: base64.StdEncoding.EncodeToString(f.orgPub), IssuedAt: f.now, ExpiresAt: f.now.Add(agentproto.EscrowKeyValid),
	}
	if mutate != nil {
		mutate(&p)
	}
	s, err := agentproto.SignEscrowKey(f.signKey, p)
	if err != nil {
		f.t.Fatal(err)
	}
	return &s
}

func TestEscrowSealsToTheOrganizationKeyAndUploads(t *testing.T) {
	f := newFx(t)
	f.a.Answered(f.signed(1, "key-1", nil))
	f.a.Sync(context.Background())

	if len(f.server.reports) != 1 || len(f.server.records) != 1 {
		t.Fatalf("reports %d, records %d", len(f.server.reports), len(f.server.records))
	}
	// The report names identifiers and nothing else.
	rep := f.server.reports[0]
	if len(rep.Volumes) != 1 || rep.Volumes[0].Protectors[0].ID != "{P1}" {
		t.Fatalf("report: %+v", rep)
	}
	rec := f.server.records[0]
	if err := rec.Check(); err != nil {
		t.Fatal(err)
	}
	// What was sent opens only with the organization's private key and the
	// record's context, and holds the password and its fingerprint.
	enc, _ := base64.StdEncoding.DecodeString(rec.Enc)
	ct, _ := base64.StdEncoding.DecodeString(rec.Ciphertext)
	c := escrowcrypto.Context{Org: org, Device: device, Volume: rec.VolumeID, Protector: rec.ProtectorID, OrgKey: "key-1"}
	pt, err := escrowcrypto.Open(f.orgPriv, c, enc, ct)
	if err != nil || string(pt) != password {
		t.Fatalf("open: %q %v", pt, err)
	}
	fp := escrowcrypto.Fingerprint("{P1}", []byte(password))
	if rec.Fingerprint != hex.EncodeToString(fp[:]) {
		t.Fatal("fingerprint")
	}
	c.Device = "dev-2"
	if _, err := escrowcrypto.Open(f.orgPriv, c, enc, ct); err == nil {
		t.Fatal("the record opens for another device")
	}
	// The password is nowhere in what was sent or logged.
	all := rec.Enc + rec.Ciphertext + rec.Fingerprint + f.logs.String()
	for _, p := range []string{password, strings.ReplaceAll(password, "-", "")} {
		if strings.Contains(all, p) {
			t.Fatal("the password is in the request or the log")
		}
	}
	// A done need is not sent again, and an unchanged report waits.
	f.now = f.now.Add(11 * time.Minute)
	f.a.Sync(context.Background())
	if len(f.server.reports) != 1 || len(f.server.records) != 1 {
		t.Fatalf("repeated: reports %d, records %d", len(f.server.reports), len(f.server.records))
	}
	// An hour later the volumes are reported again.
	f.now = f.now.Add(time.Hour)
	f.a.Sync(context.Background())
	if len(f.server.reports) != 2 {
		t.Fatalf("hourly report: %d", len(f.server.reports))
	}
}

func TestNothingHappensWithoutAVerifiedKey(t *testing.T) {
	f := newFx(t)
	f.a.Sync(context.Background())
	if len(f.server.reports) != 0 || f.reader.reads != 0 {
		t.Fatal("the agent acted without an escrow key")
	}
	// No job key pinned: nothing is trusted.
	f.a.Key = func() ed25519.PublicKey { return nil }
	f.a.Answered(f.signed(1, "key-1", nil))
	f.a.Sync(context.Background())
	if len(f.server.reports) != 0 {
		t.Fatal("an escrow key was taken with no job key pinned")
	}
	// A key signed by someone else, for another device, or expired.
	f.a.Key = func() ed25519.PublicKey { return f.signPub }
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	forged, _ := agentproto.SignEscrowKey(other, agentproto.EscrowKeyPayload{
		V: 1, DeviceID: device, OrgID: org, KeyID: "k", KeyVersion: 1, PublicKey: base64.StdEncoding.EncodeToString(f.orgPub),
		IssuedAt: f.now, ExpiresAt: f.now.Add(time.Hour)})
	f.a.Answered(&forged)
	f.a.Answered(f.signed(1, "k", func(p *agentproto.EscrowKeyPayload) { p.DeviceID = "dev-2" }))
	f.a.Answered(f.signed(1, "k", func(p *agentproto.EscrowKeyPayload) { p.ExpiresAt = f.now.Add(-time.Minute) }))
	f.a.Sync(context.Background())
	if len(f.server.reports) != 0 {
		t.Fatal("a key that does not verify was used")
	}
	// A key that expires stops escrow.
	f.a.Answered(f.signed(1, "k", nil))
	f.now = f.now.Add(25 * time.Hour)
	f.a.Sync(context.Background())
	if len(f.server.reports) != 0 {
		t.Fatal("an expired key was used")
	}
}

func TestEscrowKeyVersionNeverGoesBack(t *testing.T) {
	f := newFx(t)
	f.a.Answered(f.signed(2, "key-2", nil))
	if k := f.store.LoadEscrowKey(); k.Version != 2 || k.KeyID != "key-2" {
		t.Fatalf("stored: %+v", k)
	}
	// An older version, replayed, and another key of the same version.
	f.a.Answered(f.signed(1, "key-1", nil))
	f.a.Answered(f.signed(2, "key-other", nil))
	if k := f.store.LoadEscrowKey(); k.Version != 2 || k.KeyID != "key-2" {
		t.Fatalf("went back: %+v", k)
	}
	f.a.Sync(context.Background())
	if len(f.server.records) != 1 || f.server.records[0].KeyID != "key-2" {
		t.Fatalf("sealed to the wrong key: %+v", f.server.records)
	}
	// A newer one is taken, and survives a restart of the agent.
	f.a.Answered(f.signed(3, "key-3", nil))
	if k := f.store.LoadEscrowKey(); k.Version != 3 {
		t.Fatalf("newer not taken: %+v", k)
	}
	f2 := &escrow.Agent{DeviceID: device, Key: f.a.Key, Reader: f.reader, Server: f.server, Store: f.store, Log: f.a.Log, Now: f.a.Now}
	f2.Answered(f.signed(2, "key-2", nil))
	if k := f.store.LoadEscrowKey(); k.Version != 3 {
		t.Fatalf("a restarted agent went back: %+v", k)
	}
}

func TestEscrowKeepsToTheVolumeLimitAndRetriesStale(t *testing.T) {
	f := newFx(t)
	f.server.answer = agentproto.EscrowAnswer{State: "stale", Again: true}
	f.a.Answered(f.signed(1, "key-1", nil))
	f.a.Sync(context.Background())
	if len(f.server.records) != 1 {
		t.Fatal("no upload")
	}
	// The server said send it again: not before the server's limit allows.
	f.now = f.now.Add(time.Minute)
	f.a.Sync(context.Background())
	if len(f.server.records) != 1 || f.reader.reads != 1 {
		t.Fatalf("sent inside the limit: %d records, %d reads", len(f.server.records), f.reader.reads)
	}
	f.now = f.now.Add(escrow.VolumeEvery)
	f.server.answer = agentproto.EscrowAnswer{State: "verified"}
	f.a.Sync(context.Background())
	if len(f.server.records) != 2 {
		t.Fatalf("not retried: %d", len(f.server.records))
	}
	f.now = f.now.Add(escrow.VolumeEvery + time.Minute)
	f.a.Sync(context.Background())
	if len(f.server.records) != 2 {
		t.Fatal("sent again after verified")
	}
}

func TestEscrowSkipsWhatIsNotAPassword(t *testing.T) {
	f := newFx(t)
	f.reader.passwords[`\\?\Volume{1}\|{P1}`] = "not a recovery password"
	f.a.Answered(f.signed(1, "key-1", nil))
	f.a.Sync(context.Background())
	if len(f.server.records) != 0 {
		t.Fatal("a malformed password was sent")
	}
	if strings.Contains(f.logs.String(), "not a recovery password") {
		t.Fatal("the malformed secret was logged")
	}
}

func TestEscrowSurvivesReaderAndServerFailures(t *testing.T) {
	f := newFx(t)
	f.a.Answered(f.signed(1, "key-1", nil))
	f.reader.err = escrow.ErrUnsupported
	f.a.Sync(context.Background())
	if len(f.server.reports) != 0 {
		t.Fatal("reported with no reader")
	}
	f.reader.err = errors.New("WMI is unhappy")
	f.now = f.now.Add(11 * time.Minute)
	f.a.Sync(context.Background())
	f.reader.err = nil
	f.server.err = errors.New("503")
	f.now = f.now.Add(11 * time.Minute)
	f.a.Sync(context.Background())
	if len(f.server.records) != 0 {
		t.Fatal("recorded a failed upload")
	}
	// Once the server takes it, it goes.
	f.server.err = nil
	f.now = f.now.Add(escrow.VolumeEvery + time.Minute)
	f.a.Sync(context.Background())
	if len(f.server.records) != 1 {
		t.Fatalf("not retried: %d", len(f.server.records))
	}
}

func TestStartRunsOneSyncAtATime(t *testing.T) {
	f := newFx(t)
	f.a.Answered(f.signed(1, "key-1", nil))
	f.a.Start(context.Background())
	f.a.Start(context.Background())
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f.server.mu.Lock()
		n := len(f.server.records)
		f.server.mu.Unlock()
		if n == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the background sync did not upload")
}

func TestCapsAndSystemReaderOffWindows(t *testing.T) {
	f := newFx(t)
	if c := f.a.Caps(); len(c) != 1 || c[0] != agentproto.CapEscrow {
		t.Fatalf("caps: %v", c)
	}
	f.a.Answered(nil) // no instruction: nothing
}
