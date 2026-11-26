package agentfiles

import (
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

func TestCompareRules(t *testing.T) {
	list := []Entry{
		{Source: SourceServer, Name: "easyrmm-agent-windows-amd64.exe", Version: "v2", SHA256: "aa", Stale: true},
		{Source: SourceServer, Name: "easyrmm-agent-windows-amd64.exe", Version: "v2", SHA256: "aa"},
		{Source: SourceMesh, Name: "meshagent-windows-amd64.exe", SHA256: "bb"},
	}
	v := Compare(agentproto.InstalledFiles{AgentVersion: "v2", Files: []agentproto.InstalledFile{
		{Program: "easyrmm-agent", Name: "easyrmm-agent.exe", SHA256: "aa"},
		{Program: "meshagent", Name: "meshagent.exe", SHA256: "old"},
		{Program: "easypatch-agent", Name: "EasyPatch.Agent.exe", SHA256: "cc"},
	}}, "amd64", list)
	want := []string{StatusMatch, StatusNotCurrent, StatusNoExpected}
	for i, f := range v.Files {
		if f.Status != want[i] {
			t.Errorf("%s = %s, want %s", f.Name, f.Status, want[i])
		}
	}
	if v.Files[0].Expected == nil || v.Files[0].Expected.Stale {
		t.Error("a current entry is preferred over a stale one")
	}
	if v.PatchNote == "" {
		t.Error("the EasyPatch files say they have no expected value")
	}
	// The agent's own file is missing: shown as missing.
	v = Compare(agentproto.InstalledFiles{AgentVersion: "v2", Files: []agentproto.InstalledFile{
		{Program: "meshagent", Name: "meshagent.exe", SHA256: "bb"},
	}}, "amd64", list)
	if len(v.Missing) != 1 || v.Missing[0].Name != "easyrmm-agent.exe" {
		t.Errorf("missing = %+v", v.Missing)
	}
	// A version with no entry: no expected value, nothing missing.
	v = Compare(agentproto.InstalledFiles{AgentVersion: "v0", Files: []agentproto.InstalledFile{{Program: "easyrmm-agent", Name: "easyrmm-agent.exe", SHA256: "aa"}}}, "amd64", list)
	if v.Files[0].Status != StatusNoExpected || len(v.Missing) != 0 {
		t.Errorf("older build = %+v", v)
	}
}
