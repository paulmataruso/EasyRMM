//go:build integration

package jobkeys

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
)

func (f *fixture) issue(dev uuid.UUID, kind, id string) {
	f.t.Helper()
	f.tx(func(tx pgx.Tx) error {
		_, _, err := f.ring.Issue(f.ctx, tx, dev, kind, id)
		return err
	})
}

func (f *fixture) accept(dev uuid.UUID, rep agentproto.InstructionLogReport) LogResult {
	f.t.Helper()
	var res LogResult
	f.tx(func(tx pgx.Tx) (err error) {
		res, err = f.ring.AcceptLog(f.ctx, tx, LogDevice{ID: dev, Org: f.org, Site: f.site, Label: "pc"}, rep, f.now())
		return err
	})
	return res
}

func (f *fixture) entry(seq uint64, kind, id string, k Key, at time.Time) agentproto.LoggedInstruction {
	return agentproto.LoggedInstruction{Seq: seq, Kind: kind, ID: id, Signer: k.Fingerprint(), At: at}
}

func TestInstructionLogMatchesWhatTheServerIssued(t *testing.T) {
	f := newFixture(t)
	dev, other := f.device("pc"), f.device("other")
	k1 := f.ring.Newest()
	now := f.now()
	// One of each kind the server signs.
	for _, kind := range []string{agentproto.InstructionJob, agentproto.InstructionUpdate, agentproto.InstructionUninstall,
		agentproto.InstructionEasyPatch, agentproto.InstructionDownload, agentproto.InstructionRepair, agentproto.InstructionTrust} {
		f.issue(dev, kind, "id-"+kind)
	}
	var entries []agentproto.LoggedInstruction
	for i, kind := range []string{agentproto.InstructionJob, agentproto.InstructionUpdate, agentproto.InstructionUninstall,
		agentproto.InstructionEasyPatch, agentproto.InstructionDownload, agentproto.InstructionRepair, agentproto.InstructionTrust} {
		entries = append(entries, f.entry(uint64(i+1), kind, "id-"+kind, k1, now.Add(-time.Minute)))
	}
	res := f.accept(dev, agentproto.InstructionLogReport{Entries: entries})
	if res.Flagged != 0 || res.Ack != 7 || res.Ahead {
		t.Fatalf("matched entries: %+v", res)
	}
	if f.count(`SELECT count(*) FROM device_instruction_flags`) != 0 {
		t.Error("a matching entry was flagged")
	}

	// Each flagged when its ID, device, kind or key does not match.
	f.issue(other, agentproto.InstructionJob, "someone-elses")
	_, pub2 := f.addKey(f.now().UnixMilli(), true)
	k2, _ := f.ring.ByPublic(pub2)
	f.issue(dev, agentproto.InstructionJob, "signed-by-1")
	rogue, _, _ := ed25519.GenerateKey(rand.Reader)
	res = f.accept(dev, agentproto.InstructionLogReport{Acked: 7, Entries: []agentproto.LoggedInstruction{
		f.entry(8, agentproto.InstructionJob, "never-issued", k1, now),
		f.entry(9, agentproto.InstructionJob, "someone-elses", k1, now),
		f.entry(10, agentproto.InstructionUpdate, "id-job", k1, now),                                                // another kind
		f.entry(11, agentproto.InstructionJob, "signed-by-1", k2, now),                                              // another key
		{Seq: 12, Kind: agentproto.InstructionJob, ID: "id-job", Signer: Key{Public: rogue}.Fingerprint(), At: now}, // a key never held
		f.entry(13, agentproto.InstructionJob, "signed-by-1", k1, now),                                              // matches
	}})
	if res.Flagged != 5 || res.Ack != 13 {
		t.Fatalf("flagged %d, ack %d", res.Flagged, res.Ack)
	}
	if n := f.count(`SELECT count(*) FROM device_instruction_flags WHERE device_id = $1 AND withdrawn_at IS NULL`, dev); n != 5 {
		t.Errorf("flag rows %d", n)
	}
	// Audited with the entries: kind, ID, signer and time.
	var details string
	f.tx(func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT details::text FROM audit_log WHERE action = 'device.instruction_unknown' AND device_id = $1`, dev).Scan(&details)
	})
	if !strings.Contains(details, "never-issued") || !strings.Contains(details, k1.Fingerprint()) || !strings.Contains(details, `"kind"`) {
		t.Errorf("audit details %s", details)
	}
	// The same entries sent again (the answer did not arrive) flag nothing
	// more and audit nothing more.
	res = f.accept(dev, agentproto.InstructionLogReport{Acked: 7, Entries: []agentproto.LoggedInstruction{f.entry(8, agentproto.InstructionJob, "never-issued", k1, now)}})
	if res.Flagged != 0 || res.Ack != 13 {
		t.Errorf("a repeat: %+v", res)
	}
	if f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.instruction_unknown' AND device_id = $1`, dev) != 1 {
		t.Error("a repeat was audited again")
	}
	// Malformed entries and oversize batches are not trusted.
	res = f.accept(dev, agentproto.InstructionLogReport{Acked: 13, Entries: []agentproto.LoggedInstruction{
		{Seq: 14, Kind: "", ID: "x", Signer: k1.Fingerprint(), At: now},
		{Seq: 15, Kind: "job", ID: "x", Signer: "short", At: now},
	}})
	if res.Flagged != 0 || res.Ack != 13 {
		t.Errorf("malformed entries: %+v", res)
	}
	big := make([]agentproto.LoggedInstruction, agentproto.MaxInstructionBatch+20)
	for i := range big {
		big[i] = f.entry(uint64(100+i), agentproto.InstructionJob, "bulk", k1, now)
	}
	res = f.accept(dev, agentproto.InstructionLogReport{Acked: 13, Entries: big})
	if res.Ack != uint64(100+agentproto.MaxInstructionBatch-1) {
		t.Errorf("an oversize batch was taken whole: ack %d", res.Ack)
	}
}

func TestEntriesOlderThanNinetyDaysOrBeforeTheLastRestoreAreNotChecked(t *testing.T) {
	f := newFixture(t)
	dev := f.device("pc")
	k1 := f.ring.Newest()
	now := f.now()
	res := f.accept(dev, agentproto.InstructionLogReport{Entries: []agentproto.LoggedInstruction{
		f.entry(1, agentproto.InstructionJob, "ancient", k1, now.Add(-91*24*time.Hour)),
		f.entry(2, agentproto.InstructionJob, "recent", k1, now.Add(-time.Hour)),
	}})
	if res.Flagged != 1 || res.Ack != 2 {
		t.Fatalf("flagged %d", res.Flagged)
	}
	var id string
	f.tx(func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT instruction_id FROM device_instruction_flags WHERE device_id = $1`, dev).Scan(&id)
	})
	if id != "recent" {
		t.Errorf("flagged %q", id)
	}
	// `incident restored`: for every device, entries dated before it are not
	// checked, and flags raised for such entries are withdrawn.
	if _, err := RecordRestore(f.ctx, f.db, audit.New(f.db, nil), now); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM device_instruction_flags WHERE withdrawn_at IS NULL`); n != 0 {
		t.Errorf("flags after the restore: %d", n)
	}
	res = f.accept(dev, agentproto.InstructionLogReport{Acked: 2, Entries: []agentproto.LoggedInstruction{
		f.entry(3, agentproto.InstructionJob, "before-restore", k1, now.Add(-time.Minute)),
		f.entry(4, agentproto.InstructionJob, "after-restore", k1, now.Add(time.Minute)),
	}})
	if res.Flagged != 1 {
		t.Fatalf("after a restore: flagged %d", res.Flagged)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'server.restored' AND details->>'how' LIKE '%incident restored%'`); n != 1 {
		t.Errorf("the restore is audited %d times", n)
	}
}

// A device that says the server acknowledged more of its log than the
// database recorded: only its own entries become not checked and its own
// flags are withdrawn, another device's flag is kept, and a possible
// unrecorded restore is raised, which `incident restored` confirms.
func TestADeviceAheadOfTheRecordedLog(t *testing.T) {
	f := newFixture(t)
	dev, other := f.device("pc"), f.device("other")
	k1 := f.ring.Newest()
	now := f.now()
	f.accept(dev, agentproto.InstructionLogReport{Entries: []agentproto.LoggedInstruction{f.entry(1, agentproto.InstructionJob, "x", k1, now.Add(-time.Hour))}})
	f.accept(other, agentproto.InstructionLogReport{Entries: []agentproto.LoggedInstruction{f.entry(1, agentproto.InstructionJob, "y", k1, now.Add(-time.Hour))}})
	if f.count(`SELECT count(*) FROM device_instruction_flags WHERE withdrawn_at IS NULL`) != 2 {
		t.Fatal("setup")
	}
	f.advance(time.Minute)
	res := f.accept(dev, agentproto.InstructionLogReport{Acked: 50, Entries: []agentproto.LoggedInstruction{
		f.entry(51, agentproto.InstructionJob, "dated-before-the-heartbeat", k1, f.now().Add(-time.Second)),
	}})
	if !res.Ahead || res.Ack != 51 || res.Flagged != 0 {
		t.Fatalf("ahead: %+v", res)
	}
	if n := f.count(`SELECT count(*) FROM device_instruction_flags WHERE device_id = $1 AND withdrawn_at IS NULL`, dev); n != 0 {
		t.Errorf("the device's flags stayed: %d", n)
	}
	if n := f.count(`SELECT count(*) FROM device_instruction_flags WHERE device_id = $1 AND withdrawn_at IS NULL`, other); n != 1 {
		t.Errorf("another device's flag was withdrawn: %d", n)
	}
	// Audited with both sequences, and the server-wide alert raised.
	var claimed, recorded string
	f.tx(func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT details->>'claimed', details->>'recorded' FROM audit_log WHERE action = 'device.instruction_log_ahead' AND device_id = $1`, dev).Scan(&claimed, &recorded)
	})
	if claimed != "50" || recorded != "1" {
		t.Errorf("audit: claimed %s recorded %s", claimed, recorded)
	}
	if n := f.count(`SELECT count(*) FROM server_restores WHERE source = 'suspected' AND confirmed_at IS NULL AND $1 = ANY(devices)`, dev); n != 1 {
		t.Errorf("the possible restore is not raised: %d", n)
	}
	// Entries after the heartbeat are checked again, for that device.
	f.advance(time.Minute)
	res = f.accept(dev, agentproto.InstructionLogReport{Acked: 51, Entries: []agentproto.LoggedInstruction{f.entry(52, agentproto.InstructionJob, "later", k1, f.now())}})
	if res.Flagged != 1 || res.Ahead {
		t.Errorf("after: %+v", res)
	}
	// Until `incident restored` confirms it, nothing changes for the other
	// device: its own entries are still checked.
	res = f.accept(other, agentproto.InstructionLogReport{Acked: 1, Entries: []agentproto.LoggedInstruction{f.entry(2, agentproto.InstructionJob, "z", k1, f.now().Add(-time.Hour))}})
	if res.Flagged != 1 {
		t.Errorf("another device's entries were not checked: %+v", res)
	}
	confirmed, err := RecordRestore(f.ctx, f.db, audit.New(f.db, nil), f.now())
	if err != nil || confirmed != 1 {
		t.Fatalf("confirmed %d, %v", confirmed, err)
	}
	if n := f.count(`SELECT count(*) FROM server_restores WHERE source = 'suspected' AND confirmed_at IS NULL`); n != 0 {
		t.Error("the alert stays after the restore is confirmed")
	}
	// After the restore every device's earlier entries are not checked.
	res = f.accept(other, agentproto.InstructionLogReport{Acked: 2, Entries: []agentproto.LoggedInstruction{f.entry(3, agentproto.InstructionJob, "w", k1, f.now().Add(-time.Hour))}})
	if res.Flagged != 0 {
		t.Errorf("an earlier entry was checked after the restore: %+v", res)
	}
}

// A device enrolled again starts a new log: its row is new (the device is a
// new device), so its sequence starts from nothing and is never compared with
// what its previous identity was acknowledged.
func TestANewDeviceStartsANewSequence(t *testing.T) {
	f := newFixture(t)
	first := f.device("pc")
	k1 := f.ring.Newest()
	f.issue(first, agentproto.InstructionJob, "r1")
	f.accept(first, agentproto.InstructionLogReport{Entries: []agentproto.LoggedInstruction{f.entry(1, agentproto.InstructionJob, "r1", k1, f.now())}})
	again := f.device("pc")
	res := f.accept(again, agentproto.InstructionLogReport{Acked: 0, Entries: []agentproto.LoggedInstruction{f.entry(1, agentproto.InstructionJob, "r2", k1, f.now())}})
	if res.Ahead || res.Ack != 1 || res.Flagged != 1 {
		t.Errorf("%+v", res)
	}
}
