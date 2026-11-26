//go:build !windows

package activedirectory

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestScriptsAgainstAStandInDirectory runs every script under PowerShell 7
// against scripts/ci/winmod-ad's stand-in ActiveDirectory module: the typed
// answers, the guard (every protected class refused, nothing changed), the
// password handling (a SecureString of the right length, the text nowhere in
// the output or the calls), and the refusals of a read-only controller.
// It is skipped where pwsh is not installed. It proves the scripts' logic,
// not the real cmdlets (ADR-0075 section 9, the real-controller step).
func TestScriptsAgainstAStandInDirectory(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("pwsh is not installed")
	}
	runner, err := filepath.Abs("../../../../scripts/ci/winmod-ad/run.ps1")
	if err != nil {
		t.Fatal(err)
	}
	scripts, err := filepath.Abs("scripts")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, pwsh, "-NoProfile", "-File", runner, "-Scripts", scripts).CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("the stand-in directory run failed: %v", err)
	}
}
