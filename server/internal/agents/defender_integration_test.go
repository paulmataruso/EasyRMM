//go:build integration

package agents

import (
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

type denyOrg struct{ org uuid.UUID }

func (d denyOrg) Allowed(o uuid.UUID) bool { return o != d.org }

func (f *fixture) beatDefender(d *Device, req agentproto.HeartbeatRequest) (*agentproto.HeartbeatResponse, error) {
	f.t.Helper()
	req.Facts = agentproto.Facts{Hostname: "win", Platform: "windows", Arch: "amd64", AgentVersion: "v1"}
	return f.svc.Heartbeat(f.ctx, d, netip.MustParseAddr("192.0.2.10"), req)
}

func goodReport() *agentproto.DefenderReport {
	return &agentproto.DefenderReport{
		State: agentproto.DefenderEffective, Method: "powershell", AgentVersion: "v1",
		Kinds:   []agentproto.DefenderKind{{Kind: "path", State: agentproto.DefenderEffective}},
		Folders: []agentproto.DefenderFolder{{Path: `C:\ProgramData\EasyRMM\Agent`, Listed: true, Ours: true}},
		Events: []agentproto.DefenderEvent{
			{Kind: "add", ExclusionKind: "path", Path: `C:\ProgramData\EasyRMM\Agent`, At: time.Now().UTC()},
			{Kind: "refuse", ExclusionKind: "process", Path: `C:\x\meshagent.exe`, Reason: "Access is denied", At: time.Now().UTC()},
		},
	}
}

func goodFiles() *agentproto.InstalledFiles {
	return &agentproto.InstalledFiles{AgentVersion: "v1", ObservedAt: time.Now().UTC(), Files: []agentproto.InstalledFile{
		{Program: "easyrmm-agent", Name: "easyrmm-agent.exe", Size: 5, MD5: "d41d8cd98f00b204e9800998ecf8427e", SHA256: sum("x")},
	}}
}

func TestHeartbeatStoresDefenderAndAuditsItsEvents(t *testing.T) {
	f := newFixture(t)
	d, _ := f.enroll(f.hq, "win")
	resp, err := f.beatDefender(d, agentproto.HeartbeatRequest{Defender: goodReport(), InstalledFiles: goodFiles()})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Defender == nil || !resp.Defender.Enabled {
		t.Fatalf("policy = %+v", resp.Defender)
	}
	if n := f.count(`SELECT count(*) FROM devices WHERE id = $1 AND defender->>'state' = 'effective' AND defender_at IS NOT NULL
		AND NOT (defender ? 'events') AND installed_files->>'agentVersion' = 'v1' AND installed_files_at IS NOT NULL`, d.ID); n != 1 {
		t.Fatalf("the report was not stored: %d", n)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.defender_exclusion.add' AND device_id = $1`, d.ID); n != 1 {
		t.Fatalf("add audit rows = %d", n)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.defender_exclusion.refuse' AND device_id = $1 AND outcome = 'failure'`, d.ID); n != 1 {
		t.Fatalf("refuse audit rows = %d", n)
	}
}

func TestHeartbeatIgnoresDefenderWhereTheScopeSaysNo(t *testing.T) {
	f := newFixture(t)
	d, _ := f.enroll(f.hq, "win")
	f.svc.SetDefenderScope(denyOrg{f.org})
	resp, err := f.beatDefender(d, agentproto.HeartbeatRequest{Defender: goodReport(), InstalledFiles: goodFiles()})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Defender == nil || resp.Defender.Enabled {
		t.Fatalf("policy = %+v", resp.Defender)
	}
	if n := f.count(`SELECT count(*) FROM devices WHERE id = $1 AND (defender IS NOT NULL OR installed_files IS NOT NULL)`, d.ID); n != 0 {
		t.Fatal("a device the scope excludes had its report stored")
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action LIKE 'device.defender_exclusion.%'`); n != 0 {
		t.Fatalf("audit rows = %d", n)
	}
}

func TestHeartbeatRefusesReportsThatExceedTheCaps(t *testing.T) {
	f := newFixture(t)
	d, _ := f.enroll(f.hq, "win")
	big := goodFiles()
	for i := 0; i < agentproto.MaxInstalledFiles+1; i++ {
		big.Files = append(big.Files, big.Files[0])
	}
	if _, err := f.beatDefender(d, agentproto.HeartbeatRequest{InstalledFiles: big}); err == nil {
		t.Fatal("more files than the cap were accepted")
	}
	long := goodFiles()
	long.Files[0].Name = string(make([]byte, agentproto.MaxInstalledName+1))
	if _, err := f.beatDefender(d, agentproto.HeartbeatRequest{InstalledFiles: long}); err == nil {
		t.Fatal("a name longer than the cap was accepted")
	}
	bad := goodReport()
	bad.State = "fine"
	if _, err := f.beatDefender(d, agentproto.HeartbeatRequest{Defender: bad}); err == nil {
		t.Fatal("an unknown state was accepted")
	}
	if n := f.count(`SELECT count(*) FROM devices WHERE id = $1 AND (defender IS NOT NULL OR installed_files IS NOT NULL)`, d.ID); n != 0 {
		t.Fatal("a refused report was stored")
	}
}

func TestHeartbeatTellsWhenADeviceReportsANewVersion(t *testing.T) {
	f := newFixture(t)
	d, _ := f.enroll(f.hq, "win")
	var seen []string
	f.svc.OnAgentVersion(func(v string) { seen = append(seen, v) })
	req := agentproto.HeartbeatRequest{}
	if _, err := f.beatDefender(d, req); err != nil { // v1 over the enrolled "1"
		t.Fatal(err)
	}
	if _, err := f.beatDefender(d, req); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0] != "v1" {
		t.Fatalf("versions seen = %v", seen)
	}
}
