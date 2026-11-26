package host

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPackageInstalledAsEachManagerSaysIt(t *testing.T) {
	ctx := context.Background()
	answer := func(out string, err error) Runner {
		return func(_ context.Context, name string, args ...string) ([]byte, error) { return []byte(out), err }
	}
	for _, tc := range []struct {
		kind string
		run  Runner
		want bool
	}{
		{"deb", answer("installed\n", nil), true},
		{"deb", answer("config-files", nil), false}, // removed, configuration kept
		{"deb", answer("", errors.New("no packages found")), false},
		{"rpm", answer("easyrmm-agent-1.2.3-1.x86_64", nil), true},
		{"rpm", answer("package easyrmm-agent is not installed", errors.New("exit 1")), false},
		{"zip", answer("installed", nil), false},
	} {
		if got := PackageInstalled(ctx, tc.run, tc.kind); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.kind, got, tc.want)
		}
	}
	if runtime.GOOS != "windows" && PackageInstalled(ctx, nil, "msi") {
		t.Error("an MSI is installed without Windows Installer")
	}
	for _, k := range PackageKinds {
		if PackageRemoveCommand(k) == "" {
			t.Errorf("no removal command for %s", k)
		}
	}
	if !strings.Contains(PackageRemoveCommand("deb"), "apt-get purge") {
		t.Error("the DEB's removal is purge, which leaves no config-files state")
	}
}

func TestEnrollmentPathsAndTheCopy(t *testing.T) {
	l := Paths{Root: "/r", OS: "linux"}
	if l.EnrollmentFile() != "/r/etc/easyrmm-agent/install.conf" || l.EnrollmentTop() != "/r/etc" ||
		l.PackageCopy() != "/r/usr/libexec/easyrmm-agent/easyrmm-agent" {
		t.Errorf("linux: %s %s %s", l.EnrollmentFile(), l.EnrollmentTop(), l.PackageCopy())
	}
	w := Paths{Root: "/r", OS: "windows"}
	for got, want := range map[string]string{
		w.EnrollmentFile(): filepath.Join("/r", "Program Files", "EasyRMM", "Package", "Enrollment", "install.conf"),
		w.EnrollmentTop():  filepath.Join("/r", "Program Files", "EasyRMM"),
		w.PackageCopy():    filepath.Join("/r", "Program Files", "EasyRMM", "Package", "easyrmm-agent.exe"),
	} {
		if got != want {
			t.Errorf("windows: %s, want %s", got, want)
		}
	}
}

func TestSystemdEnableDoesNotStart(t *testing.T) {
	var calls []string
	s := Systemd{Dir: t.TempDir(), Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, nil
	}}
	var _ Enabler = s
	svc := Paths{Root: "/", OS: "linux"}.AgentService()
	if err := s.Enable(context.Background(), svc); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(calls, ";"); got != "systemctl daemon-reload;systemctl enable easyrmm-agent.service" {
		t.Errorf("calls = %s", got)
	}
	if b, err := os.ReadFile(filepath.Join(s.Dir, svc.Name)); err != nil || !strings.Contains(string(b), "time-sync.target") {
		t.Errorf("unit: %v", err)
	}
}

func TestInstallExecutableReplacesALinkToThePackageCopy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("links need a privilege on Windows")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "copy")
	if err := os.WriteFile(src, []byte("the program"), 0o755); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "bin", "agent")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(src, dst); err != nil {
		t.Fatal(err)
	}
	// The link's content equals the program, and still it is replaced.
	changed, err := InstallExecutable(src, dst)
	if err != nil || !changed {
		t.Fatalf("InstallExecutable: %v, %v", changed, err)
	}
	if fi, err := os.Lstat(dst); err != nil || fi.Mode()&os.ModeSymlink != 0 {
		t.Errorf("the link was kept: %v", err)
	}
	if changed, err := InstallExecutable(src, dst); err != nil || changed {
		t.Errorf("a second install changed it: %v, %v", changed, err)
	}
}

func TestStartForbiddenAsPolicyRCDAnswers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("policy-rc.d is Debian's")
	}
	root := t.TempDir()
	p := Paths{Root: root, OS: "linux"}
	path := filepath.Join(root, "usr/sbin/policy-rc.d")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if StartForbidden(context.Background(), p, Exec) {
		t.Error("no policy-rc.d forbids")
	}
	for code, want := range map[int]bool{101: true, 0: false, 104: false} {
		if err := os.WriteFile(path, []byte(fmt.Sprintf("#!/bin/sh\nexit %d\n", code)), 0o755); err != nil {
			t.Fatal(err)
		}
		if got := StartForbidden(context.Background(), p, Exec); got != want {
			t.Errorf("policy-rc.d exit %d: forbidden = %v", code, got)
		}
	}
}

func TestSystemdInstalledNeedsItsFilesAndSystemctl(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("systemd is Linux's")
	}
	root := t.TempDir()
	p := Paths{Root: root, OS: "linux"}
	bin := t.TempDir()
	t.Setenv("PATH", bin)
	if SystemdInstalled(p) {
		t.Error("systemd installed in an empty root")
	}
	if err := os.MkdirAll(filepath.Join(root, "usr/lib/systemd/system"), 0o755); err != nil {
		t.Fatal(err)
	}
	if SystemdInstalled(p) {
		t.Error("systemd installed without systemctl")
	}
	if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !SystemdInstalled(p) {
		t.Error("systemd not found where its directory and systemctl are")
	}
}
