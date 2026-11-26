package inventory

import (
	"context"
	"crypto/md5" //nolint:gosec // the test checks the reported MD5
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

func write(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestInstalledReportsBothHashesAndVersions(t *testing.T) {
	d := t.TempDir()
	agent, mesh := filepath.Join(d, "a", "easyrmm-agent.exe"), filepath.Join(d, "m", "meshagent.exe")
	write(t, agent, "agent bytes")
	write(t, mesh, "mesh bytes")
	write(t, filepath.Join(d, "p", "EasyPatch.Agent.exe"), "patch")
	write(t, filepath.Join(d, "p", "lib", "x.dll"), "dll")
	meshAsked := 0
	i := &Installed{AgentExe: agent, MeshExe: mesh, PatchDir: filepath.Join(d, "p"), AgentVersion: "v1",
		MeshVersion:  func(context.Context) string { meshAsked++; return "mesh 1.2" },
		PatchVersion: func(context.Context) string { return "0.9" }}
	r := i.Due(context.Background())
	if r == nil || len(r.Files) != 4 || r.MeshAgentVersion != "mesh 1.2" || r.PatchAgentVersion != "0.9" || r.AgentVersion != "v1" {
		t.Fatalf("report = %+v", r)
	}
	if err := r.Check(); err != nil {
		t.Fatal(err)
	}
	m, s := md5.Sum([]byte("agent bytes")), sha256.Sum256([]byte("agent bytes")) //nolint:gosec // see the import
	var got agentproto.InstalledFile
	for _, f := range r.Files {
		if f.Program == agentproto.InstalledAgent {
			got = f
		}
	}
	if got.MD5 != hex.EncodeToString(m[:]) || got.SHA256 != hex.EncodeToString(s[:]) || got.Name != "easyrmm-agent.exe" || got.Size != 11 {
		t.Fatalf("agent file = %+v", got)
	}
	if i.Due(context.Background()) != nil {
		t.Fatal("nothing changed and it is not a day later, yet a report was due")
	}
	if meshAsked != 1 {
		t.Fatalf("MeshAgent's version was asked %d times", meshAsked)
	}
}

func TestInstalledSendsAgainWhenABuildChangesOrADayPasses(t *testing.T) {
	d := t.TempDir()
	agent := filepath.Join(d, "easyrmm-agent.exe")
	write(t, agent, "one")
	now := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	i := &Installed{AgentExe: agent, AgentVersion: "v1", Now: func() time.Time { return now }}
	first := i.Due(context.Background())
	if first == nil {
		t.Fatal("the first report is due at once")
	}
	// A self-update: new bytes, new version, in the next heartbeat.
	write(t, agent, "two, longer")
	i.AgentVersion = "v2"
	r := i.Due(context.Background())
	if r == nil || r.AgentVersion != "v2" || r.Files[0].SHA256 == first.Files[0].SHA256 {
		t.Fatalf("after an update: %+v", r)
	}
	if i.Due(context.Background()) != nil {
		t.Fatal("a report with nothing new")
	}
	now = now.Add(Every + time.Minute)
	if i.Due(context.Background()) == nil {
		t.Fatal("a day later a report is due")
	}
}

func TestInstalledCapsTheFileCount(t *testing.T) {
	d := t.TempDir()
	for n := range 80 {
		write(t, filepath.Join(d, "p", "f"+string(rune('a'+n/26))+string(rune('a'+n%26))+".dll"), "x")
	}
	r := (&Installed{PatchDir: filepath.Join(d, "p")}).Due(context.Background())
	if r == nil || len(r.Files) != agentproto.MaxInstalledFiles || r.Check() != nil {
		t.Fatalf("report = %d files", len(r.Files))
	}
}
