//go:build integration

package easypatch

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
)

func (f *fixture) seenAt(device uuid.UUID) *time.Time {
	f.t.Helper()
	var at *time.Time
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT agent_seen_at FROM easypatch_devices WHERE device_id = $1`, device).Scan(&at)
	}); err != nil {
		f.t.Fatal(err)
	}
	return at
}

// The poll reads each engine organization's endpoints with one list call
// and stores the agents' last check-ins.
func TestPollAgentsStoresCheckIns(t *testing.T) {
	f := newPatching(t)
	seen := time.Now().Add(-3 * time.Minute).UTC().Truncate(time.Microsecond)
	f.ep.Set(func() { f.e1.LastCheckIn = &seen })
	before := len(f.ep.RequestsTo("GET", "/api/v1/endpoints"))
	if err := f.svc.PollAgents(f.ctx); err != nil {
		t.Fatal(err)
	}
	if got := len(f.ep.RequestsTo("GET", "/api/v1/endpoints")) - before; got != 1 {
		t.Errorf("%d list calls for one engine organization, want 1", got)
	}
	if at := f.seenAt(f.web); at == nil || !at.Equal(seen) {
		t.Errorf("web-01 seen at %v, want %v", at, seen)
	}
	// db-01's endpoint has the engine's fixed time.
	if at := f.seenAt(f.db); at == nil || at.Year() != 2026 {
		t.Errorf("db-01 seen at %v", at)
	}
	// An endpoint that is not linked (app-01's fingerprint did not match)
	// has none.
	if at := f.seenAt(f.app); at != nil {
		t.Errorf("an unlinked device was given a check-in: %v", at)
	}
	// Nothing is judged just after the first answer.
	if f.svc.AgentsSettled(time.Now()) {
		t.Error("judged at once")
	}
}

// Nothing is judged while the engine does not answer, or for 15 minutes
// after it does again.
func TestAgentsAreJudgedOnlyWhenTheEngineHasAnsweredForAWhile(t *testing.T) {
	f := newPatching(t)
	now := time.Now()
	clock := now
	f.svc.SetClock(func() time.Time { return clock })
	poll := func(d time.Duration) error {
		clock = now.Add(d)
		return f.svc.PollAgents(f.ctx)
	}
	if f.svc.AgentsSettled(now) {
		t.Fatal("settled before any poll")
	}
	for _, d := range []time.Duration{0, 5 * time.Minute, 10 * time.Minute} {
		if err := poll(d); err != nil {
			t.Fatal(err)
		}
		if f.svc.AgentsSettled(now.Add(d)) {
			t.Errorf("settled %v after the first answer", d)
		}
	}
	if err := poll(15 * time.Minute); err != nil {
		t.Fatal(err)
	}
	if !f.svc.AgentsSettled(now.Add(15 * time.Minute)) {
		t.Error("not settled after 15 minutes of answers")
	}
	// The engine goes away: nothing is judged, and its return starts the
	// 15 minutes again.
	f.ep.Set(func() { f.ep.Down = true })
	if err := poll(20 * time.Minute); err == nil {
		t.Error("a poll of an engine that is down did not fail")
	}
	if f.svc.AgentsSettled(now.Add(20 * time.Minute)) {
		t.Error("settled while the engine is down")
	}
	f.ep.Set(func() { f.ep.Down = false })
	for _, d := range []time.Duration{25 * time.Minute, 30 * time.Minute, 35 * time.Minute} {
		if err := poll(d); err != nil {
			t.Fatal(err)
		}
		if f.svc.AgentsSettled(now.Add(d)) {
			t.Errorf("settled %v after the engine returned at 25 minutes", d-25*time.Minute)
		}
	}
	if err := poll(40 * time.Minute); err != nil {
		t.Fatal(err)
	}
	if !f.svc.AgentsSettled(now.Add(40 * time.Minute)) {
		t.Error("not settled 15 minutes after the engine returned")
	}
	// Polls that stopped are an unreachable engine too.
	if f.svc.AgentsSettled(now.Add(60 * time.Minute)) {
		t.Error("settled on a last answer an hour old")
	}
}

// RepairOffer offers the packages of the version the device has, never the
// newest, and says why when it cannot.
func TestRepairOfferIsTheInstalledVersion(t *testing.T) {
	f := newInstall(t)
	// The device has the engine's current version and an older one is also
	// listed for Windows.
	f.report(f.lin, "", &agentproto.EasyPatchAgent{Version: eptest.EngineVersion, Status: "Active"})
	offer, why, err := f.svc.RepairOffer(f.ctx, f.lin)
	if err != nil || why != "" || offer == nil || len(offer.Packages) != 2 {
		t.Fatalf("offer %+v, %q, %v", offer, why, err)
	}
	if offer.Packages[0].Format != "deb" || offer.Packages[1].Format != "rpm" || offer.Packages[0].Version != eptest.EngineVersion ||
		!strings.HasPrefix(offer.Packages[0].URL, "https://patch.example.com/downloads/agent/EasyPatchAgent-"+eptest.EngineVersion) {
		t.Errorf("packages %+v", offer.Packages)
	}
	// It is what the agent accepts in a repair instruction.
	p := agentproto.RepairPayload{V: agentproto.RepairPayloadVersion, ID: "x", DeviceID: f.lin.String(), Target: agentproto.TargetEasyPatchAgent,
		Step: agentproto.StepRepair, ExpiresAt: time.Now().Add(time.Minute), EasyPatch: offer}
	pub, priv, _ := ed25519.GenerateKey(nil)
	s, err := agentproto.SignRepair(priv, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agentproto.VerifyRepair(pub, s, f.lin.String(), time.Now()); err != nil {
		t.Errorf("the agent would refuse the offer: %v", err)
	}

	// An older version installed gets the older package, where the engine
	// still has it.
	f.report(f.win, "", &agentproto.EasyPatchAgent{Version: "1.8.2", Status: "Active"})
	offer, why, err = f.svc.RepairOffer(f.ctx, f.win)
	if err != nil || why != "" || len(offer.Packages) != 1 || offer.Packages[0].Version != "1.8.2" {
		t.Errorf("older version: %+v, %q, %v", offer, why, err)
	}
	// A version the engine no longer has cannot be repaired in place.
	f.report(f.win, "", &agentproto.EasyPatchAgent{Version: "1.2.3", Status: "Active"})
	if offer, why, _ := f.svc.RepairOffer(f.ctx, f.win); offer != nil || !strings.Contains(why, "no longer offers version 1.2.3") {
		t.Errorf("a version the engine dropped: %+v, %q", offer, why)
	}
	// Unknown version, architecture and platform.
	f.report(f.mac, "", nil)
	if offer, why, _ := f.svc.RepairOffer(f.ctx, f.mac); offer != nil || why == "" {
		t.Errorf("macOS: %+v, %q", offer, why)
	}
	if offer, why, _ := f.svc.RepairOffer(f.ctx, f.x86); offer != nil || !strings.Contains(why, "386") {
		t.Errorf("386: %+v, %q", offer, why)
	}
	if offer, why, _ := f.svc.RepairOffer(f.ctx, f.noInv); offer != nil || !strings.Contains(why, "version") {
		t.Errorf("no version known: %+v, %q", offer, why)
	}
	// A device that is leaving is offered nothing.
	f.exec(`INSERT INTO easypatch_opt_outs (device_id) VALUES ($1)`, f.lin)
	if offer, why, _ := f.svc.RepairOffer(f.ctx, f.lin); offer != nil || !strings.Contains(why, "leaving") {
		t.Errorf("a device that is leaving: %+v, %q", offer, why)
	}
}
