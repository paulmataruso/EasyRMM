//go:build integration

package agents

import (
	"encoding/json"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/agentsettings"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

const hbKey = agentsettings.HeartbeatKey

// A heartbeat of an agent with the report for signed settings.
type settingsBeat struct {
	sha     string
	version string
	caps    *agentproto.SettingsCapabilities
	report  *agentproto.SettingsReport
	secs    int
	signed  time.Time
}

func (f *keyed) settingsBeat(d *Device, b settingsBeat) *agentproto.HeartbeatResponse {
	f.t.Helper()
	if b.version == "" {
		b.version = "v1"
	}
	ctx := f.ctx
	if !b.signed.IsZero() {
		ctx = WithSignedAt(ctx, b.signed)
	}
	resp, err := f.svc.Heartbeat(ctx, d, netip.MustParseAddr("192.0.2.10"), agentproto.HeartbeatRequest{
		Facts:        agentproto.Facts{Hostname: "h", Platform: "linux", Arch: "amd64", AgentVersion: b.version, AgentSHA256: b.sha},
		Capabilities: b.caps, Settings: b.report, HeartbeatSeconds: b.secs,
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return resp
}

func takes(keys map[string]int) *agentproto.SettingsCapabilities {
	return &agentproto.SettingsCapabilities{Accepts: []string{agentproto.CapSettings}, Settings: keys}
}

var heartbeatV1 = map[string]int{hbKey: 1}

func (f *keyed) state(d *Device) agentsettings.State {
	f.t.Helper()
	var st agentsettings.State
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		var err error
		st, err = agentsettings.ReadState(f.ctx, tx, d.ID)
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return st
}

func (f *keyed) verified(d *Device, resp *agentproto.HeartbeatResponse) agentproto.SettingsPayload {
	f.t.Helper()
	if resp.Settings == nil {
		f.t.Fatal("the answer carries no settings document")
	}
	p, err := agentproto.VerifySettings(f.k1.Public, *resp.Settings, d.ID.String())
	if err != nil {
		f.t.Fatalf("the document does not verify: %v", err)
	}
	return p
}

func (f *keyed) setSite(value string) {
	f.t.Helper()
	f.exec(`DELETE FROM agent_settings WHERE key = $1 AND scope = 'site'`, hbKey)
	f.exec(`INSERT INTO agent_settings (key, scope, organization_id, site_id, value) VALUES ($1, 'site', $2, $3, $4::jsonb)`, hbKey, f.org, f.hq, value)
}

func TestDocumentsGoOnlyToAgentsThatReportTheCapability(t *testing.T) {
	f := newKeyed(t)
	d, _ := f.enroll(f.hq, "srv")
	f.setSite("300")

	// No report: no document, and nothing is stored but the time.
	if resp := f.settingsBeat(d, settingsBeat{sha: oldSHA}); resp.Settings != nil {
		t.Fatal("a document went to a heartbeat without the report")
	}
	if st := f.state(d); st.Capabilities != nil || st.DocVersion != 0 {
		t.Fatalf("state after a heartbeat without the report: %+v", st)
	}
	// A report that does not list settings.v1 (an agent that takes only
	// another message): stored, no document.
	other := &agentproto.SettingsCapabilities{Accepts: []string{"channel.v1"}, Settings: heartbeatV1}
	if resp := f.settingsBeat(d, settingsBeat{sha: oldSHA, caps: other, report: &agentproto.SettingsReport{}}); resp.Settings != nil {
		t.Fatal("a document went to an agent that does not list settings.v1")
	}
	if st := f.state(d); st.Capabilities == nil || st.DocVersion != 0 {
		t.Fatalf("report not stored: %+v", st)
	}
	// With settings.v1: the device's effective settings, signed by the job
	// key, for the device, with a version from the clock.
	resp := f.settingsBeat(d, settingsBeat{sha: oldSHA, caps: takes(heartbeatV1), report: &agentproto.SettingsReport{}, secs: 60})
	p := f.verified(d, resp)
	if p.Version != f.clock.UnixMilli() || string(p.Settings[hbKey]) != "300" || len(p.Settings) != 1 || p.DeviceID != d.ID.String() {
		t.Fatalf("document: %+v", p)
	}
	if resp.HeartbeatSeconds != 300 {
		t.Errorf("the answer's interval: %d", resp.HeartbeatSeconds)
	}
	st := f.state(d)
	if st.DocVersion != p.Version || st.DocHash != agentproto.SettingsHash(p.Settings) || st.DocCatalogVersion != agentsettings.CatalogVersion || st.NotAppliedHeartbeats != 0 {
		t.Errorf("state: %+v", st)
	}
	// The server signed it with the key the device trusts, and recorded it.
	if n := f.count(`SELECT count(*) FROM issued_instructions WHERE device_id = $1 AND kind = 'settings'`, d.ID); n != 1 {
		t.Errorf("issued instructions: %d", n)
	}
	// Another key does not verify it.
	if _, err := agentproto.VerifySettings(agentproto.Keys{}, *resp.Settings, d.ID.String()); err == nil {
		t.Error("verified with no key")
	}
}

func TestDocumentsCarryOnlyKeysAndValuesTheReportAllows(t *testing.T) {
	f := newKeyed(t)
	d, _ := f.enroll(f.hq, "srv")
	beat := func(keys map[string]int) *agentproto.SettingsPayload {
		t.Helper()
		resp := f.settingsBeat(d, settingsBeat{sha: oldSHA, caps: takes(keys), report: &agentproto.SettingsReport{Version: f.state(d).AppliedVersion}})
		if resp.Settings == nil {
			return nil
		}
		p := f.verified(d, resp)
		return &p
	}
	// A key the server does not know is left out; so is one reported at
	// version 0, which no schema of the server's is at or below.
	f.clock = f.clock.Add(time.Second)
	p := beat(map[string]int{hbKey: 1, "logs.collect": 1})
	if p == nil || len(p.Settings) != 1 || string(p.Settings[hbKey]) != "60" {
		t.Fatalf("an unknown key: %+v", p)
	}
	f.clock = f.clock.Add(time.Second)
	if p := beat(map[string]int{hbKey: 0}); p == nil || len(p.Settings) != 0 {
		t.Fatalf("a key at version 0: %+v", p)
	}
	// An agent reporting a newer schema version than the server knows is
	// judged by the highest the server knows at or below it.
	f.clock = f.clock.Add(time.Second)
	if p := beat(map[string]int{hbKey: 7}); p == nil || string(p.Settings[hbKey]) != "60" {
		t.Fatalf("a newer schema version: %+v", p)
	}
	// A value the schema does not allow is left out too. A platform minimum
	// above the agent's bounds cannot be set; a stored value outside them
	// (written under a catalog that allowed it) is ignored by Resolve, so
	// the default is sent. Here a value inside the bounds is sent as it is.
	f.setSite("45")
	f.clock = f.clock.Add(time.Second)
	if p := beat(heartbeatV1); p == nil || string(p.Settings[hbKey]) != "45" {
		t.Fatalf("a site's value: %+v", p)
	}
	// An oversize or malformed report is ignored: nothing stored, no document.
	bad := &agentproto.SettingsCapabilities{Accepts: []string{agentproto.CapSettings}, Settings: map[string]int{"": 1}}
	f.clock = f.clock.Add(time.Second)
	if resp := f.settingsBeat(d, settingsBeat{sha: oldSHA, caps: bad}); resp.Settings != nil {
		t.Error("a malformed report got a document")
	}
}

func TestVersionsOnlyRise(t *testing.T) {
	f := newKeyed(t)
	d, _ := f.enroll(f.hq, "srv")
	f.setSite("120")
	report := func(v int64) *agentproto.SettingsReport { return &agentproto.SettingsReport{Version: v} }

	first := f.verified(d, f.settingsBeat(d, settingsBeat{sha: oldSHA, caps: takes(heartbeatV1), report: report(0)}))
	// The agent holds it: nothing more is sent, nothing changes.
	if resp := f.settingsBeat(d, settingsBeat{sha: oldSHA, caps: takes(heartbeatV1), report: report(first.Version)}); resp.Settings != nil {
		t.Fatal("the agent holds the current version, and was sent it again")
	}
	st := f.state(d)
	if st.AppliedVersion != first.Version || st.AppliedHash != st.DocHash || st.AppliedAt.IsZero() || st.NotAppliedHeartbeats != 0 {
		t.Errorf("applied: %+v", st)
	}
	// A change at the same millisecond still rises.
	f.setSite("150")
	second := f.verified(d, f.settingsBeat(d, settingsBeat{sha: oldSHA, caps: takes(heartbeatV1), report: report(first.Version)}))
	if second.Version != first.Version+1 || string(second.Settings[hbKey]) != "150" {
		t.Fatalf("second: %+v after %+v", second, first)
	}
	// An agent that has not applied it is sent the same document again, the
	// same version and content.
	again := f.verified(d, f.settingsBeat(d, settingsBeat{sha: oldSHA, caps: takes(heartbeatV1), report: report(first.Version)}))
	if again.Version != second.Version || agentproto.SettingsHash(again.Settings) != agentproto.SettingsHash(second.Settings) || !again.IssuedAt.Equal(second.IssuedAt) {
		t.Errorf("resent: %+v", again)
	}
	// The clock rises: the next version is the time.
	f.clock = f.clock.Add(time.Minute)
	f.setSite("200")
	third := f.verified(d, f.settingsBeat(d, settingsBeat{sha: oldSHA, caps: takes(heartbeatV1), report: report(second.Version)}))
	if third.Version != f.clock.UnixMilli() {
		t.Errorf("third %d, the time %d", third.Version, f.clock.UnixMilli())
	}

	// A restore: the stored versions are set back, as a database restored from
	// a backup would be. The agent reports a version above the last issued, so
	// the server issues a new one above it even if nothing changed.
	f.exec(`UPDATE agent_device_state SET doc_version = $2 WHERE device_id = $1`, d.ID, first.Version)
	f.clock = f.clock.Add(-time.Hour) // and the server's clock set back
	restored := f.verified(d, f.settingsBeat(d, settingsBeat{sha: oldSHA, caps: takes(heartbeatV1), report: report(third.Version), signed: f.clock.Add(48 * time.Hour)}))
	if restored.Version != third.Version+1 || string(restored.Settings[hbKey]) != "200" {
		t.Fatalf("after a restore: %+v, the agent reported %d", restored, third.Version)
	}
	// Both ends up on a document this server issued: the next heartbeat
	// reporting it applied gets nothing.
	if resp := f.settingsBeat(d, settingsBeat{sha: oldSHA, caps: takes(heartbeatV1), report: report(restored.Version), signed: f.clock.Add(49 * time.Hour)}); resp.Settings != nil {
		t.Error("sent again after the restore was applied")
	}

	// A reported version above 2^53 - 1 is not used: the server issues from
	// its own sequence and shows the report as a problem.
	f.clock = f.clock.Add(2 * time.Hour)
	f.setSite("90")
	huge := f.verified(d, f.settingsBeat(d, settingsBeat{sha: oldSHA, caps: takes(heartbeatV1), report: report(1 << 60), signed: f.clock.Add(50 * time.Hour)}))
	if huge.Version <= restored.Version || huge.Version > agentproto.MaxSettingsVersion {
		t.Errorf("after an out-of-range report: %d", huge.Version)
	}
	if st := f.state(d); st.AppliedVersion != 0 || !strings.Contains(st.Problems[agentproto.SettingsDocumentKey], "2^53") {
		t.Errorf("the out-of-range report: %+v", st)
	}
}

func TestTwoHeartbeatsAtOnceIssueOneVersion(t *testing.T) {
	f := newKeyed(t)
	d, _ := f.enroll(f.hq, "srv")
	f.setSite("120")
	const n = 8
	versions := make([]int64, n)
	hashes := make([]string, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := f.svc.Heartbeat(f.ctx, d, netip.MustParseAddr("192.0.2.10"), agentproto.HeartbeatRequest{
				Facts:        agentproto.Facts{Hostname: "h", Platform: "linux", Arch: "amd64", AgentVersion: "v1", AgentSHA256: oldSHA},
				Capabilities: takes(heartbeatV1), Settings: &agentproto.SettingsReport{},
			})
			if err != nil || resp.Settings == nil {
				t.Errorf("heartbeat %d: %v %v", i, err, resp)
				return
			}
			p, err := agentproto.VerifySettings(f.k1.Public, *resp.Settings, d.ID.String())
			if err != nil {
				t.Errorf("heartbeat %d: %v", i, err)
				return
			}
			versions[i], hashes[i] = p.Version, agentproto.SettingsHash(p.Settings)
		}()
	}
	wg.Wait()
	for i := range n {
		if versions[i] != versions[0] || hashes[i] != hashes[0] || versions[i] == 0 {
			t.Fatalf("heartbeat %d got version %d (%s), heartbeat 0 got %d (%s)", i, versions[i], hashes[i], versions[0], hashes[0])
		}
	}
	if st := f.state(d); st.DocVersion != versions[0] {
		t.Errorf("stored %d, issued %d", st.DocVersion, versions[0])
	}
}

func TestNotAppliedAfterThreeReportingHeartbeats(t *testing.T) {
	f := newKeyed(t)
	d, _ := f.enroll(f.hq, "srv")
	f.setSite("120")
	beat := func(applied int64) *agentproto.HeartbeatResponse {
		return f.settingsBeat(d, settingsBeat{sha: oldSHA, caps: takes(heartbeatV1), report: &agentproto.SettingsReport{Version: applied}})
	}
	doc := f.verified(d, beat(0))
	for i, want := range []int{1, 2, 3} {
		beat(0)
		if st := f.state(d); st.NotAppliedHeartbeats != want || st.NotApplied() != (i == 2) {
			t.Fatalf("after %d heartbeats: %+v", i+1, st)
		}
	}
	// A heartbeat without the report counts toward nothing, and leaves the
	// count where it was.
	f.settingsBeat(d, settingsBeat{sha: oldSHA})
	f.settingsBeat(d, settingsBeat{sha: oldSHA})
	if st := f.state(d); st.NotAppliedHeartbeats != 3 || !st.NotApplied() {
		t.Errorf("heartbeats without the report: %+v", st)
	}
	// The agent applies it: the flag goes.
	beat(doc.Version)
	if st := f.state(d); st.NotAppliedHeartbeats != 0 || st.NotApplied() || st.AppliedVersion != doc.Version {
		t.Errorf("after applying: %+v", st)
	}
	// A new version resets the count, and the heartbeat that carries it does
	// not count.
	f.setSite("150")
	beat(doc.Version)
	if st := f.state(d); st.NotAppliedHeartbeats != 0 {
		t.Errorf("the heartbeat that issued the version counted: %+v", st)
	}
	beat(doc.Version)
	if st := f.state(d); st.NotAppliedHeartbeats != 1 {
		t.Errorf("the next one: %+v", st)
	}

	// An instance whose catalog is older than the document's counts nothing
	// and leaves the document in place, though the setting changed.
	f.exec(`UPDATE agent_device_state SET doc_catalog_version = $2, not_applied_heartbeats = 0 WHERE device_id = $1`, d.ID, agentsettings.CatalogVersion+1)
	before := f.state(d)
	f.setSite("200")
	for range 4 {
		if resp := beat(doc.Version); resp.Settings != nil {
			t.Fatal("an older catalog replaced a newer one's document")
		}
	}
	after := f.state(d)
	if after.NotAppliedHeartbeats != 0 || after.DocVersion != before.DocVersion || after.DocHash != before.DocHash || after.NotApplied() {
		t.Errorf("an older instance changed the state: before %+v after %+v", before, after)
	}
}

func TestTheReportHoldsWhileTheBuildDoes(t *testing.T) {
	f := newKeyed(t)
	d, _ := f.enroll(f.hq, "srv")
	f.settingsBeat(d, settingsBeat{sha: oldSHA, caps: takes(heartbeatV1), report: &agentproto.SettingsReport{}})
	// The first heartbeat of a process: no report; the last holds.
	f.settingsBeat(d, settingsBeat{sha: oldSHA})
	if st := f.state(d); st.Capabilities == nil || st.Build != oldSHA {
		t.Fatalf("the report did not hold: %+v", st)
	}
	// A change of build without a report ends it.
	f.settingsBeat(d, settingsBeat{sha: strings.Repeat("b", 64)})
	if st := f.state(d); st.Capabilities != nil {
		t.Fatalf("a change of build kept the report: %+v", st)
	}
	// No document goes to a device that reports nothing.
	f.setSite("120")
	if resp := f.settingsBeat(d, settingsBeat{sha: strings.Repeat("b", 64)}); resp.Settings != nil {
		t.Error("a document went to an agent that reports nothing")
	}
	// An agent that sends no hash is identified by its version.
	f.settingsBeat(d, settingsBeat{version: "v9", caps: takes(heartbeatV1), report: &agentproto.SettingsReport{}})
	f.settingsBeat(d, settingsBeat{version: "v9"})
	if st := f.state(d); st.Capabilities == nil || st.Build != "version:v9" {
		t.Errorf("an agent with no hash: %+v", st)
	}
	f.settingsBeat(d, settingsBeat{version: "v10"})
	if st := f.state(d); st.Capabilities != nil {
		t.Errorf("a new version without a hash kept the report: %+v", st)
	}
}

func TestAHeartbeatSignedEarlierMovesNothing(t *testing.T) {
	f := newKeyed(t)
	d, _ := f.enroll(f.hq, "srv")
	now := f.clock
	f.setSite("120")
	f.settingsBeat(d, settingsBeat{sha: oldSHA, caps: takes(heartbeatV1), report: &agentproto.SettingsReport{}, signed: now})
	if st := f.state(d); !st.SignedAt.Equal(now) {
		t.Fatalf("signed time %v, want %v", st.SignedAt, now)
	}
	// One signed before: its time is not stored, its report not taken, and it
	// gets no document and counts for nothing.
	early := f.settingsBeat(d, settingsBeat{sha: oldSHA, caps: takes(map[string]int{hbKey: 9}), report: &agentproto.SettingsReport{Version: 77}, signed: now.Add(-time.Second)})
	if early.Settings != nil {
		t.Error("a heartbeat signed earlier got a document")
	}
	st := f.state(d)
	if !st.SignedAt.Equal(now) || st.AppliedVersion != 0 || st.Capabilities.Settings[hbKey] != 1 || st.NotAppliedHeartbeats != 0 {
		t.Errorf("an earlier heartbeat moved the state: %+v", st)
	}
	// A later one does.
	f.settingsBeat(d, settingsBeat{sha: oldSHA, caps: takes(heartbeatV1), report: &agentproto.SettingsReport{}, signed: now.Add(time.Second)})
	if st := f.state(d); !st.SignedAt.Equal(now.Add(time.Second)) {
		t.Errorf("a later heartbeat did not move the time: %v", st.SignedAt)
	}
}

func TestTheIntervalTheAgentReportsIsKept(t *testing.T) {
	f := newKeyed(t)
	d, _ := f.enroll(f.hq, "srv")
	read := func() (secs int, window time.Duration, updated time.Time) {
		t.Helper()
		if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
			var seen, until time.Time
			if err := tx.QueryRow(f.ctx, `SELECT agent_heartbeat_seconds, agent_last_seen_at, agent_online_until, updated_at FROM devices WHERE id = $1`, d.ID).
				Scan(&secs, &seen, &until, &updated); err != nil {
				return err
			}
			window = until.Sub(seen)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return
	}
	f.setSite("300")
	// An agent that reports none (an older build): the interval answered.
	f.settingsBeat(d, settingsBeat{sha: oldSHA})
	if secs, window, _ := read(); secs != 300 || window != 15*time.Minute {
		t.Fatalf("an agent that reports none: %d, online for %s", secs, window)
	}
	// An agent reporting 60 seconds while the server answers 300 (it holds an
	// older document, say): the server keeps what the agent uses.
	f.settingsBeat(d, settingsBeat{sha: oldSHA, caps: takes(heartbeatV1), report: &agentproto.SettingsReport{}, secs: 60})
	secs, window, updated := read()
	if secs != 60 || window != 3*time.Minute {
		t.Fatalf("the agent's report: %d, online for %s", secs, window)
	}
	// The first heartbeat of a process has no report: the kept interval stays,
	// though the answer says 300.
	f.settingsBeat(d, settingsBeat{sha: oldSHA})
	if secs, window, _ := read(); secs != 60 || window != 3*time.Minute {
		t.Errorf("a heartbeat without the report moved the interval: %d, online for %s", secs, window)
	}
	// 300 reported: online for 15 minutes.
	f.settingsBeat(d, settingsBeat{sha: oldSHA, caps: takes(heartbeatV1), report: &agentproto.SettingsReport{}, secs: 300})
	secs, window, after := read()
	if secs != 300 || window != 15*time.Minute {
		t.Errorf("300 reported: %d, online for %s", secs, window)
	}
	if !after.Equal(updated) {
		t.Errorf("updated_at moved from %v to %v", updated, after)
	}
	// A value the database does not keep is not used: the answered one is.
	f.settingsBeat(d, settingsBeat{sha: oldSHA, caps: takes(heartbeatV1), report: &agentproto.SettingsReport{}, secs: 5})
	if secs, _, _ := read(); secs != 300 {
		t.Errorf("a reported interval of 5 seconds: %d", secs)
	}
	// A change of build without a report: the answered interval again.
	f.setSite("120")
	f.settingsBeat(d, settingsBeat{sha: strings.Repeat("c", 64)})
	if secs, _, _ := read(); secs != 120 {
		t.Errorf("after a change of build: %d", secs)
	}
}

func TestAChangeForAnOrganizationIsIssuedLazilyToEachDevice(t *testing.T) {
	f := newKeyed(t)
	a, _ := f.enroll(f.hq, "a")
	b, _ := f.enroll(f.hq, "b")
	for _, d := range []*Device{a, b} {
		f.verified(d, f.settingsBeat(d, settingsBeat{sha: oldSHA, caps: takes(heartbeatV1), report: &agentproto.SettingsReport{}}))
	}
	f.clock = f.clock.Add(time.Second)
	f.exec(`INSERT INTO agent_settings (key, scope, organization_id, value) VALUES ($1, 'organization', $2, '240')`, hbKey, f.org)
	// Nothing is written per device by the change: their rows still hold the
	// old document until each checks in.
	if n := f.count(`SELECT count(*) FROM agent_device_state WHERE doc_version < $1`, f.clock.UnixMilli()); n != 2 {
		t.Fatalf("rows changed by the setting: %d", n)
	}
	for _, d := range []*Device{a, b} {
		p := f.verified(d, f.settingsBeat(d, settingsBeat{sha: oldSHA, caps: takes(heartbeatV1), report: &agentproto.SettingsReport{Version: f.state(d).DocVersion}}))
		if string(p.Settings[hbKey]) != "240" || p.Version != f.clock.UnixMilli() {
			t.Errorf("%s: %+v", d.ID, p)
		}
	}
}

func TestTheStateGoesWithTheDeviceAndReportsAreStoredBounded(t *testing.T) {
	f := newKeyed(t)
	d, _ := f.enroll(f.hq, "srv")
	f.settingsBeat(d, settingsBeat{sha: oldSHA, caps: takes(heartbeatV1), report: &agentproto.SettingsReport{
		Problems: map[string]string{hbKey: agentproto.ProblemClamped, agentproto.SettingsDocumentKey: "refused: key x was not reported"}}})
	st := f.state(d)
	if st.Problems[hbKey] != agentproto.ProblemClamped || !strings.HasPrefix(st.Problems[agentproto.SettingsDocumentKey], "refused: ") {
		t.Errorf("problems: %+v", st.Problems)
	}
	// Problems too long for the bounds are not stored.
	long := map[string]string{hbKey: strings.Repeat("x", agentproto.MaxSettingsReason+1)}
	f.settingsBeat(d, settingsBeat{sha: oldSHA, caps: takes(heartbeatV1), report: &agentproto.SettingsReport{Problems: long}})
	if st := f.state(d); len(st.Problems) != 0 {
		t.Errorf("an oversize problem was stored: %v", st.Problems)
	}
	b, _ := json.Marshal(st.Capabilities)
	if !strings.Contains(string(b), agentproto.CapSettings) {
		t.Errorf("capabilities: %s", b)
	}
	f.exec(`DELETE FROM devices WHERE id = $1`, d.ID)
	if n := f.count(`SELECT count(*) FROM agent_device_state WHERE device_id = $1`, d.ID); n != 0 {
		t.Errorf("the state outlived its device: %d", n)
	}
}
