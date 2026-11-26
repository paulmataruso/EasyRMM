package agentproto

import (
	"strings"
	"testing"
	"time"
)

func goodDefender() DefenderReport {
	return DefenderReport{
		State: DefenderEffective, Method: "powershell", AgentVersion: "v1",
		Kinds:   []DefenderKind{{Kind: "path", State: DefenderEffective}, {Kind: "asr", State: DefenderNotNeeded, Reason: "off"}},
		Folders: []DefenderFolder{{Path: `C:\ProgramData\EasyRMM\Agent`, Listed: true, Ours: true}},
		Events:  []DefenderEvent{{Kind: DefenderEventAdd, ExclusionKind: "path", Path: `C:\x`, At: time.Now()}, {Kind: DefenderEventLock, Path: `C:\x`}},
	}
}

func TestDefenderReportCheck(t *testing.T) {
	good := goodDefender()
	if err := good.Check(); err != nil {
		t.Fatal(err)
	}
	if DefenderAuditAction("add") != "device.defender_exclusion.add" {
		t.Error("audit action")
	}
	long := strings.Repeat("x", MaxDefenderText+1)
	for name, edit := range map[string]func(*DefenderReport){
		"unknown state":        func(r *DefenderReport) { r.State = "fine" },
		"not_needed overall":   func(r *DefenderReport) { r.State = DefenderNotNeeded },
		"too many kinds":       func(r *DefenderReport) { r.Kinds = make([]DefenderKind, len(DefenderKinds)+1) },
		"too many folders":     func(r *DefenderReport) { r.Folders = make([]DefenderFolder, MaxDefenderFolders+1) },
		"too many events":      func(r *DefenderReport) { r.Events = make([]DefenderEvent, MaxDefenderEvents+1) },
		"bad kind":             func(r *DefenderReport) { r.Kinds[0].Kind = "extension" },
		"bad kind state":       func(r *DefenderReport) { r.Kinds[0].State = "x" },
		"long kind reason":     func(r *DefenderReport) { r.Kinds[0].Reason = long },
		"empty folder":         func(r *DefenderReport) { r.Folders[0].Path = "" },
		"long folder reason":   func(r *DefenderReport) { r.Folders[0].Reason = long },
		"unknown event":        func(r *DefenderReport) { r.Events[0].Kind = "delete" },
		"bad event kind":       func(r *DefenderReport) { r.Events[0].ExclusionKind = "x" },
		"long event path":      func(r *DefenderReport) { r.Events[0].Path = strings.Repeat("p", MaxInstalledName+1) },
		"long reason":          func(r *DefenderReport) { r.Reason = long },
		"long method":          func(r *DefenderReport) { r.Method = strings.Repeat("m", 17) },
		"long version":         func(r *DefenderReport) { r.AgentVersion = strings.Repeat("v", 65) },
		"long event reason":    func(r *DefenderReport) { r.Events[0].Reason = long },
		"too many folders (2)": func(r *DefenderReport) { r.Kinds = nil; r.Folders = make([]DefenderFolder, 17) },
	} {
		r := goodDefender()
		edit(&r)
		if r.Check() == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func goodFiles() InstalledFiles {
	return InstalledFiles{AgentVersion: "v1", Files: []InstalledFile{
		{Program: InstalledAgent, Name: "easyrmm-agent.exe", Size: 3, MD5: strings.Repeat("a", 32), SHA256: strings.Repeat("b", 64)},
		{Program: InstalledMeshAgent, Name: "meshagent.exe", MD5: strings.Repeat("a", 32), SHA256: strings.Repeat("b", 64)},
		{Program: InstalledPatchAgent, Name: "EasyPatch.Agent.exe", MD5: strings.Repeat("a", 32), SHA256: strings.Repeat("b", 64)},
	}}
}

func TestInstalledFilesCheck(t *testing.T) {
	good := goodFiles()
	if err := good.Check(); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*InstalledFiles){
		"too many files":    func(f *InstalledFiles) { f.Files = make([]InstalledFile, MaxInstalledFiles+1) },
		"unknown program":   func(f *InstalledFiles) { f.Files[0].Program = "cmd" },
		"empty name":        func(f *InstalledFiles) { f.Files[0].Name = "" },
		"long name":         func(f *InstalledFiles) { f.Files[0].Name = strings.Repeat("n", MaxInstalledName+1) },
		"a path as a name":  func(f *InstalledFiles) { f.Files[0].Name = `..\evil.exe` },
		"bad md5":           func(f *InstalledFiles) { f.Files[0].MD5 = "xyz" },
		"upper-case sha":    func(f *InstalledFiles) { f.Files[0].SHA256 = strings.Repeat("B", 64) },
		"negative size":     func(f *InstalledFiles) { f.Files[0].Size = -1 },
		"long version":      func(f *InstalledFiles) { f.AgentVersion = strings.Repeat("v", 65) },
		"long mesh version": func(f *InstalledFiles) { f.MeshAgentVersion = strings.Repeat("v", 65) },
		"too large a whole": func(f *InstalledFiles) {
			f.Files = nil
			for range MaxInstalledFiles {
				f.Files = append(f.Files, InstalledFile{Program: InstalledAgent, Name: strings.Repeat("n", MaxInstalledName), MD5: strings.Repeat("a", 32), SHA256: strings.Repeat("b", 64)})
			}
		},
	} {
		f := goodFiles()
		edit(&f)
		if f.Check() == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestCheckEasyPatchReportIsNestedOnceWithoutEvents(t *testing.T) {
	ok := &DefenderReport{State: DefenderEffective, EasyPatch: &DefenderReport{State: DefenderNotApplicable, Reason: "third-party antivirus"}}
	if err := ok.Check(); err != nil {
		t.Fatal(err)
	}
	bad := []*DefenderReport{
		{State: DefenderEffective, EasyPatch: &DefenderReport{State: "bogus"}},
		{State: DefenderEffective, EasyPatch: &DefenderReport{State: DefenderEffective, EasyPatch: &DefenderReport{State: DefenderEffective}}},
		{State: DefenderEffective, EasyPatch: &DefenderReport{State: DefenderEffective, Events: []DefenderEvent{{Kind: DefenderEventAdd}}}},
	}
	for i, r := range bad {
		if r.Check() == nil {
			t.Errorf("report %d was accepted", i)
		}
	}
}
