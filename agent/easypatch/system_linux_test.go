package easypatch

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// fakeTools puts scripts named like the package managers on PATH. Each
// appends its arguments to calls.log and exits with the code in
// <name>.exit, if any.
func fakeTools(t *testing.T, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, n := range names {
		script := "#!/bin/sh\necho \"" + n + " $*\" >> " + filepath.Join(dir, "calls.log") + "\n" +
			"f=" + filepath.Join(dir, n+".exit") + "\nif [ -f \"$f\" ]; then code=$(head -n1 \"$f\"); sed -i 1d \"$f\"; exit \"$code\"; fi\n"
		if err := os.WriteFile(filepath.Join(dir, n), []byte(script), 0o755); err != nil { //nolint:gosec // a test script
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+"/usr/bin:/bin")
	return dir
}

func calls(t *testing.T, dir string) string {
	b, _ := os.ReadFile(filepath.Join(dir, "calls.log"))
	return string(b)
}

func exits(t *testing.T, dir, name string, codes ...string) {
	if err := os.WriteFile(filepath.Join(dir, name+".exit"), []byte(strings.Join(codes, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxFormats(t *testing.T) {
	systemd := t.TempDir()
	root := func() int { return 0 }
	dir := fakeTools(t, "apt-get", "dnf")
	t.Setenv("PATH", dir) // only the fakes, not the machine's own
	l := linuxSystem{euid: root, systemd: systemd}
	if got, err := l.Formats(); err != nil || strings.Join(got, ",") != "deb,rpm" {
		t.Errorf("both: %v %v", got, err)
	}
	if err := os.Remove(filepath.Join(dir, "apt-get")); err != nil {
		t.Fatal(err)
	}
	if got, err := l.Formats(); err != nil || strings.Join(got, ",") != "rpm" {
		t.Errorf("dnf: %v %v", got, err)
	}
	t.Setenv("PATH", t.TempDir())
	if _, err := l.Formats(); err == nil || !strings.Contains(err.Error(), "neither") {
		t.Errorf("neither: %v", err)
	}
	if _, err := (linuxSystem{euid: root, systemd: filepath.Join(systemd, "missing")}).Formats(); err == nil ||
		!strings.Contains(err.Error(), "systemd") {
		t.Errorf("no systemd: %v", err)
	}
	if _, err := (linuxSystem{euid: func() int { return 1000 }, systemd: systemd}).Formats(); err == nil ||
		!strings.Contains(err.Error(), "root") {
		t.Errorf("not root: %v", err)
	}
	if p, ok := platform().(linuxSystem); !ok || p.agent != linuxAgent || p.systemd != "/run/systemd/system" {
		t.Errorf("platform: %+v", platform())
	}
}

func TestLinuxInstall(t *testing.T) {
	ctx := context.Background()
	p := payload(time.Now(), agentproto.EasyPatchDeb)
	deb := agentproto.EasyPatchPackage{FileName: "a.deb", Format: agentproto.EasyPatchDeb}
	rpm := agentproto.EasyPatchPackage{FileName: "a.rpm", Format: agentproto.EasyPatchRPM}
	l := linuxSystem{}

	dir := fakeTools(t, "apt-get", "dnf")
	if err := l.Install(ctx, &p, deb, "/tmp/a.deb"); err != nil {
		t.Fatal(err)
	}
	if got := calls(t, dir); got != "apt-get install -y --no-install-recommends -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold /tmp/a.deb\n" {
		t.Errorf("deb: %q", got)
	}

	// A failure refreshes the package lists and tries again.
	dir = fakeTools(t, "apt-get")
	exits(t, dir, "apt-get", "100", "0", "100")
	err := l.Install(ctx, &p, deb, "/tmp/a.deb")
	if err == nil || !strings.Contains(err.Error(), "apt-get could not install the EasyPatch agent (exit code 100)") {
		t.Errorf("deb failing: %v", err)
	}
	if got := calls(t, dir); strings.Count(got, "apt-get install") != 2 || !strings.Contains(got, "apt-get update\n") {
		t.Errorf("deb retry: %q", got)
	}

	dir = fakeTools(t, "dnf")
	if err := l.Install(ctx, &p, rpm, "/tmp/a.rpm"); err != nil {
		t.Fatal(err)
	}
	exits(t, dir, "dnf", "1")
	if err := l.Install(ctx, &p, rpm, "/tmp/a.rpm"); err == nil || !strings.Contains(err.Error(), "dnf could not install") {
		t.Errorf("rpm failing: %v", err)
	}
	if got := calls(t, dir); got != "dnf install -y /tmp/a.rpm\ndnf install -y /tmp/a.rpm\n" {
		t.Errorf("rpm: %q", got)
	}
	// An RPM database left needing recovery (RHEL 8's Berkeley DB) names the fix.
	dir = t.TempDir()
	damaged := "#!/bin/sh\necho 'error: rpmdb: BDB0113 Thread/process 1234/0 failed: BDB1507 Thread died in Berkeley DB library'\n" +
		"echo 'error: db5 error(-30973) from dbenv->failchk: BDB0087 DB_RUNRECOVERY: Fatal error, run database recovery'\n" +
		"echo 'error: cannot open Packages index using db5 - (-30973)'\necho 'Error: Error: rpmdb open failed'\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "dnf"), []byte(damaged), 0o755); err != nil { //nolint:gosec // a test script
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+"/usr/bin:/bin")
	err = l.Install(ctx, &p, rpm, "/tmp/a.rpm")
	if err == nil || !strings.Contains(err.Error(), "dnf could not install the EasyPatch agent (exit code 1)") ||
		!strings.Contains(err.Error(), "run rpm --rebuilddb as root, then install again") {
		t.Errorf("damaged RPM database: %v", err)
	}
	if rpmDatabaseDamaged([]byte("Error: Unable to find a match: easypatch-agent")) {
		t.Error("an ordinary dnf failure taken for a damaged database")
	}

	t.Setenv("PATH", t.TempDir())
	if err := l.Install(ctx, &p, rpm, "/tmp/a.rpm"); err == nil || !strings.Contains(err.Error(), "running dnf") {
		t.Errorf("no dnf: %v", err)
	}
}

func TestLinuxEnroll(t *testing.T) {
	ctx := context.Background()
	p := payload(time.Now(), agentproto.EasyPatchDeb)
	dir := t.TempDir()
	agent := filepath.Join(dir, "easypatch-agent")
	got := filepath.Join(dir, "got")
	l := linuxSystem{agent: agent}
	if err := l.Enroll(ctx, &p); err == nil || !strings.Contains(err.Error(), "not at") {
		t.Errorf("missing agent: %v", err)
	}
	// The token arrives on standard input, never in the arguments.
	write := func(code string) {
		script := "#!/bin/sh\necho \"$*\" > " + got + "\ncat >> " + got + "\necho \"echoed $(tail -n1 " + got + ")\"\nexit " + code + "\n"
		if err := os.WriteFile(agent, []byte(script), 0o755); err != nil { //nolint:gosec // a test script
			t.Fatal(err)
		}
	}
	write("0")
	if err := l.Enroll(ctx, &p); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(got)
	if string(b) != "enroll --server https://patch.example.com --token-file -\n"+testToken {
		t.Errorf("enroll saw %q", b)
	}
	write("9")
	if err := l.Enroll(ctx, &p); err == nil || !strings.Contains(err.Error(), "echoed [token]") || strings.Contains(err.Error(), testToken) {
		t.Errorf("failure: %v", err)
	}
	if err := os.Chmod(agent, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := l.Enroll(ctx, &p); err == nil || !strings.Contains(err.Error(), "running easypatch-agent") {
		t.Errorf("not executable: %v", err)
	}
}

// TestLinuxEnrollServerCA: the instruction's certificate authority reaches
// the EasyPatch agent as a file for --server-ca, gone afterwards; an agent
// from before that option is enrolled again without it.
func TestLinuxEnrollServerCA(t *testing.T) {
	ctx := context.Background()
	p := payload(time.Now(), agentproto.EasyPatchDeb)
	p.CACert = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	dir := t.TempDir()
	agent := filepath.Join(dir, "easypatch-agent")
	got := filepath.Join(dir, "got")
	l := linuxSystem{agent: agent}
	// The script records its arguments, the CA file's path and contents,
	// and the token; withCA and without are its exit codes.
	write := func(withCA, without string) {
		script := "#!/bin/sh\necho \"$*\" >> " + got + "\ncode=" + without + "\nprev=\nfor a; do\n" +
			"  if [ \"$prev\" = --server-ca ]; then echo \"$a\" >> " + got + "; cat \"$a\" >> " + got + "; code=" + withCA + "; fi\n" +
			"  prev=$a\ndone\ncat >> " + got + "\necho >> " + got + "\nexit $code\n"
		if err := os.WriteFile(agent, []byte(script), 0o755); err != nil { //nolint:gosec // a test script
			t.Fatal(err)
		}
		_ = os.Remove(got)
	}
	lines := func() []string {
		b, _ := os.ReadFile(got)
		return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	}

	write("0", "9")
	if err := l.Enroll(ctx, &p); err != nil {
		t.Fatal(err)
	}
	seen := lines()
	if len(seen) < 3 || !strings.HasPrefix(seen[0], "enroll --server https://patch.example.com --token-file - --server-ca /") ||
		!strings.Contains(strings.Join(seen, "\n"), p.CACert+testToken) {
		t.Fatalf("enroll saw %q", seen)
	}
	if _, err := os.Stat(seen[1]); !os.IsNotExist(err) {
		t.Errorf("the CA file %s is left behind: %v", seen[1], err)
	}

	// An agent without the option: enrolled again, without it.
	write("2", "0")
	if err := l.Enroll(ctx, &p); err != nil {
		t.Fatal(err)
	}
	var calls []string
	for _, line := range lines() {
		if strings.HasPrefix(line, "enroll ") {
			calls = append(calls, line)
		}
	}
	if len(calls) != 2 || !strings.Contains(calls[0], "--server-ca") || calls[1] != "enroll --server https://patch.example.com --token-file -" {
		t.Errorf("fallback called %q", calls)
	}
	// It cannot reach EasyPatch: the store is the way.
	write("2", "6")
	if err := l.Enroll(ctx, &p); err == nil || !strings.Contains(err.Error(), "system's certificate store") {
		t.Errorf("old agent, unreachable: %v", err)
	}
	// A current agent given the CA that still cannot reach EasyPatch: not
	// a matter of the store.
	write("6", "0")
	if err := l.Enroll(ctx, &p); err == nil || strings.Contains(err.Error(), "certificate store") || !strings.Contains(err.Error(), "exit code 6") {
		t.Errorf("unreachable with the CA: %v", err)
	}
}
