//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	agentclient "github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/agent/host"
	agentjobs "github.com/paulmataruso/easyrmm/agent/jobs"
	"github.com/paulmataruso/easyrmm/agent/runner"
	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/agent/trust"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// The real agent's key store and instruction log (agent/trust) against the
// real server (ADR-0057 slice 1): the agent reports the keys it trusts, the
// scripts it runs are in its log and match what the server signed, and a key
// the server never issued, put on the device the way `trust-key --force` does,
// is flagged and audited, then cleared when the server's key is back.
type keyAgent struct {
	ks    *trust.KeyStore
	il    *trust.InstructionLog
	store state.Store
}

func (f *chanFixture) startKeyAgent() *keyAgent {
	t := f.t
	tr := f.h.srv.Client().Transport.(*http.Transport).Clone()
	addr := f.h.srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	tr.TLSClientConfig = &tls.Config{RootCAs: tr.TLSClientConfig.RootCAs, ServerName: "example.com", MinVersion: tls.VersionTLS12}
	c, err := agentclient.New(agentclient.Options{Server: publicOrigin, Version: "1.2.3-test", Transport: tr})
	if err != nil {
		t.Fatal(err)
	}
	c.SetIdentity(f.deviceID, f.key)
	store, _, err := state.Open(host.Paths{Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &state.Config{Server: publicOrigin, DeviceID: f.deviceID}
	if err := store.Save(cfg, f.key); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a := &keyAgent{store: store}
	a.il = &trust.InstructionLog{Store: store, Log: log}
	a.ks = &trust.KeyStore{DeviceID: f.deviceID, Install: agentproto.InstallID(f.key.Public().(ed25519.PublicKey)), Config: cfg, Store: store, Log: log, Record: a.il.Record}
	w := &agentjobs.Worker{Client: c, DeviceID: f.deviceID, Dir: t.TempDir(), Log: log, MinRetry: 100 * time.Millisecond, MaxRetry: time.Second,
		Keys: a.ks.Keys, Dropped: a.ks.Dropped, Report: a.ks.Report, Record: a.il.Record}
	r := &runner.Runner{
		Client: c, Store: store, DeviceID: f.deviceID, Log: log, Keys: a.ks.Keys, JobKeys: a.ks, Instructions: a.il, Record: a.il.Record,
		Accepts: agentjobs.Accepts(),
		Facts:   func() agentproto.Facts { return facts("chan-01") },
		Every:   150 * time.Millisecond, MinWake: 20 * time.Millisecond,
		OnJobKey: func(k string, gen int64) {
			had := len(a.ks.Keys())
			if ok, _ := a.ks.Pin(k, gen); ok && had == 0 {
				w.KeysChanged()
			}
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { _ = w.Run(ctx) })
	wg.Go(func() { _ = r.Run(ctx) })
	t.Cleanup(func() { cancel(); wg.Wait() })
	return a
}

func (f *chanFixture) count(sql string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.h.db.DB.ReadTx(context.Background(), database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), sql, args...).Scan(&n)
	}); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func TestAgentFollowsTheRingAndTheTripwiresShow(t *testing.T) {
	f := newChanFixture(t, false)
	a := f.startKeyAgent()
	server := f.h.deps.JobKeys.Newest()

	// The first answer pins the key and its generation; from the next
	// heartbeat on, the agent reports what it trusts.
	eventuallyT(t, 20*time.Second, "the agent's report is stored", func() bool {
		return f.count(`SELECT count(*) FROM devices WHERE id = $1 AND job_keys_report IS NOT NULL AND job_keys_first_reported_at IS NOT NULL`, f.deviceID) == 1
	})
	if r := a.ks.Report(); len(r) != 1 || r[0].Key != server.Encoded() || r[0].Generation != 1 {
		t.Fatalf("the agent trusts %+v", r)
	}
	if f.count(`SELECT count(*) FROM device_unknown_keys WHERE device_id = $1`, f.deviceID) != 0 {
		t.Fatal("the server's own key is flagged")
	}

	// A script it runs is in its log, signed by the server's key, and the
	// server's record of what it issued matches it: no flag; the log is
	// acknowledged and dropped.
	f.runJob("first")
	eventuallyT(t, 20*time.Second, "the log entry is acknowledged", func() bool {
		return f.count(`SELECT count(*) FROM device_instruction_log WHERE device_id = $1 AND acked_seq >= 1`, f.deviceID) == 1 &&
			len(a.il.Report(true).Entries) == 0
	})
	if f.count(`SELECT count(*) FROM issued_instructions WHERE device_id = $1 AND kind = 'job' AND generation = 1`, f.deviceID) == 0 {
		t.Error("the server recorded nothing it signed")
	}
	if f.count(`SELECT count(*) FROM device_instruction_flags WHERE device_id = $1`, f.deviceID) != 0 {
		t.Fatal("a job the server issued was flagged")
	}
	if latest := a.il.Latest(5); len(latest) == 0 || latest[len(latest)-1].Kind != agentproto.InstructionJob || latest[len(latest)-1].Signer != server.Fingerprint() {
		t.Errorf("the log %+v", latest)
	}

	// Someone puts a key the server never issued on the device, as
	// `trust-key --force` does: flagged and audited, once.
	rogue, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := a.ks.Replace(time.Now().UnixMilli(), agentproto.EncodeKey(rogue), true); err != nil {
		t.Fatal(err)
	}
	eventuallyT(t, 20*time.Second, "the unknown key is flagged", func() bool {
		return f.count(`SELECT count(*) FROM device_unknown_keys WHERE device_id = $1 AND fingerprint = $2`, f.deviceID, agentproto.Fingerprint(rogue)) == 1
	})
	time.Sleep(600 * time.Millisecond) // several heartbeats: audited once
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.job_key_unknown' AND device_id = $1`, f.deviceID); n != 1 {
		t.Errorf("audited %d times", n)
	}
	// With the server's key back, the flag clears, audited, and a script runs.
	if err := a.ks.Replace(1, server.Encoded(), true); err != nil {
		t.Fatal(err)
	}
	eventuallyT(t, 20*time.Second, "the flag is cleared", func() bool {
		return f.count(`SELECT count(*) FROM device_unknown_keys WHERE device_id = $1`, f.deviceID) == 0
	})
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.job_key_unknown_cleared' AND device_id = $1`, f.deviceID); n != 1 {
		t.Errorf("clearing audited %d times", n)
	}
	f.runJob("after")
	if f.count(`SELECT count(*) FROM device_instruction_flags WHERE device_id = $1`, f.deviceID) != 0 {
		t.Error("a job after the key came back was flagged")
	}
}
