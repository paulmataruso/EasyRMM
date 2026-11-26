package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/agent/defender"
	"github.com/paulmataruso/easyrmm/agent/host"
)

func TestDefenderIsWindowsOnlyAndOnTheMachinesOwnFolders(t *testing.T) {
	h := newHarness(t)
	for name, paths := range map[string]host.Paths{
		"linux":                     h.e.paths,
		"windows under a test root": {Root: t.TempDir(), OS: "windows"},
	} {
		h.e.paths = paths
		if h.e.defenderManager() != nil || h.e.installedFiles() != nil {
			t.Errorf("%s: a manager was built where there is no Defender to manage", name)
		}
		h.e.defenderInstall(context.Background())
		h.e.defenderRepair(context.Background())
		if left := h.e.defenderRemove(); left != nil {
			t.Errorf("%s: removed %v", name, left)
		}
		h.e.defenderKeep(&defender.Record{Version: 1, Entries: []defender.Entry{{Kind: "path", Path: "x"}}})
	}
	h.e.defenderKeep(nil)
}

func TestDefenderManagerNamesTheThreeFoldersAndTwoPrograms(t *testing.T) {
	t.Setenv("ProgramData", `C:\ProgramData`)
	t.Setenv("ProgramFiles", `C:\Program Files`)
	h := newHarness(t)
	h.e.paths = host.Paths{OS: "windows"}
	m := h.e.defenderManager()
	if m == nil {
		t.Fatal("no manager on the machine's own Windows layout")
	}
	norm := func(s []string) []string {
		out := make([]string, len(s))
		for i, x := range s {
			out[i] = strings.ReplaceAll(x, "/", `\`)
		}
		return out
	}
	folders := strings.Join(norm(m.Folders), "|")
	for _, want := range []string{`ProgramData\EasyRMM\Agent`, `Program Files\EasyRMM\Agent`, `Program Files\EasyRMM\MeshAgent`} {
		if !strings.Contains(folders, want) {
			t.Errorf("folders %v lack %s", m.Folders, want)
		}
	}
	programs := strings.Join(norm(m.Programs), "|")
	if !strings.Contains(programs, `easyrmm-agent.exe`) || !strings.Contains(programs, `meshagent.exe`) || len(m.Programs) != 2 {
		t.Errorf("programs = %v", m.Programs)
	}
	if filepath.Base(m.RecordFile) != defender.RecordFile {
		t.Errorf("record = %s", m.RecordFile)
	}
	if in := h.e.installedFiles(); in == nil || in.AgentVersion != Version {
		t.Errorf("installed files = %+v", in)
	}
}

func TestMeshBuildReadsTheCompileLine(t *testing.T) {
	linuxOnly(t)
	dir := t.TempDir()
	exe := filepath.Join(dir, "meshagent")
	script := "#!/bin/sh\necho 'MeshCentral Agent'\necho 'Compiled on: Nov  3 2025, 09:22:24'\n"
	if err := os.WriteFile(exe, []byte(script), 0o755); err != nil { //nolint:gosec // a test program
		t.Fatal(err)
	}
	if got := meshBuild(context.Background(), exe); got != "Compiled on: Nov  3 2025, 09:22:24" {
		t.Errorf("build = %q", got)
	}
	if got := meshBuild(context.Background(), filepath.Join(dir, "missing")); got != "" {
		t.Errorf("a missing program = %q", got)
	}
}
