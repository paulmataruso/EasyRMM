//go:build windows

package escrow_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/agent/escrow"
)

// BitLocker's WMI, as the agent calls it, on a file-backed virtual disk, as
// LocalSystem (the account the agent's service runs as). Nothing here encrypts
// a volume and the runner's system drive is never touched: the tests add and
// remove recovery-password protectors on a 64 MiB data volume made for the
// test (a rotation's steps), and read the computer's preconditions. They run
// only where EASYRMM_TEST_BITLOCKER=1 and BitLocker's WMI class exists (a
// Windows Server image without the BitLocker feature has none, which these
// tests report and skip), and TPM-dependent steps (the TPM protector and
// encryption) are not exercised: the runner has no TPM.

var numericalPassword = regexp.MustCompile(`^(\d{6}-){7}\d{6}$`)

// vhd makes, attaches and formats a small virtual disk with a drive letter, and
// removes it when the test ends.
func vhd(t *testing.T) string {
	t.Helper()
	if os.Getenv("EASYRMM_TEST_BITLOCKER") != "1" {
		t.Skip("set EASYRMM_TEST_BITLOCKER=1 to run against BitLocker's WMI (Windows, administrator, a BitLocker-capable edition)")
	}
	if _, err := (escrow.SystemReader{}).Volumes(context.Background()); err != nil {
		t.Skipf("BitLocker's WMI class is not on this computer: %v", err)
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "escrow-test.vhd")
	letter := ""
	for _, l := range "ZYXWVUTSR" {
		if _, err := os.Stat(string(l) + `:\`); err != nil {
			letter = string(l)
			break
		}
	}
	if letter == "" {
		t.Skip("no free drive letter")
	}
	diskpart := func(script string) {
		t.Helper()
		f := filepath.Join(dir, fmt.Sprintf("dp-%d.txt", time.Now().UnixNano()))
		if err := os.WriteFile(f, []byte(script), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("diskpart.exe", "/s", f).CombinedOutput(); err != nil {
			t.Fatalf("diskpart: %v\n%s", err, out)
		}
	}
	diskpart(fmt.Sprintf("create vdisk file=%s maximum=64 type=fixed\nselect vdisk file=%s\nattach vdisk\ncreate partition primary\nformat fs=ntfs quick label=EASYRMM\nassign letter=%s\n", file, file, letter))
	t.Cleanup(func() {
		diskpart(fmt.Sprintf("select vdisk file=%s\ndetach vdisk\n", file))
	})
	return letter + ":"
}

func TestWindowsPreconditionsAreRead(t *testing.T) {
	if os.Getenv("EASYRMM_TEST_BITLOCKER") != "1" {
		t.Skip("set EASYRMM_TEST_BITLOCKER=1")
	}
	p, err := (escrow.SystemManager{}).Preconditions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	host, _ := os.Hostname()
	if !strings.EqualFold(p.Computer, host) {
		t.Fatalf("computer %q, host %q", p.Computer, host)
	}
	if p.DomainController {
		t.Fatal("a CI runner is not a domain controller")
	}
	t.Logf("edition has BitLocker: %v, TPM ready: %v, restart pending: %v", p.EditionAllows, p.TPMReady, p.RebootPending)
}

func TestWindowsRecoveryPasswordProtectorsAddReadAndRemove(t *testing.T) {
	letter := vhd(t)
	ctx := context.Background()
	m, r := escrow.SystemManager{}, escrow.SystemReader{}

	vol, err := m.Volume(ctx, letter)
	if err != nil || vol == nil {
		t.Fatalf("the volume: %+v %v", vol, err)
	}
	if vol.Status != "decrypted" || vol.AnyProtectors || len(vol.Protectors) != 0 {
		t.Fatalf("a new volume: %+v", vol)
	}
	// A letter nothing has is no volume, not an error.
	if got, err := m.Volume(ctx, "Q:"); err != nil || (got != nil && letter != "Q:") {
		t.Fatalf("a letter that is not a volume: %+v %v", got, err)
	}
	// An unencrypted volume with a drive letter is one the console offers to
	// turn BitLocker on for: the reader lists it.
	vols, err := r.Volumes(ctx)
	if err != nil || !slices.ContainsFunc(vols, func(v escrow.Volume) bool { return v.ID == vol.ID && v.Status == "decrypted" }) {
		t.Fatalf("the reader does not list the unencrypted volume: %v %v", vols, err)
	}

	// A rotation's steps: add one, read it, add the next, remove the first.
	first, err := m.AddRecoveryPassword(ctx, vol.ID)
	if err != nil || first == "" {
		t.Fatalf("add: %q %v", first, err)
	}
	pw1, err := r.RecoveryPassword(ctx, vol.ID, first)
	if err != nil || !numericalPassword.Match(pw1) {
		t.Fatalf("read: a password of the expected form: %v", err)
	}
	second, err := m.AddRecoveryPassword(ctx, vol.ID)
	if err != nil || second == first {
		t.Fatalf("second add: %q %v", second, err)
	}
	pw2, _ := r.RecoveryPassword(ctx, vol.ID, second)
	if string(pw1) == string(pw2) {
		t.Fatal("two protectors have the same password")
	}
	if now, _ := m.Volume(ctx, letter); now == nil || len(now.Protectors) != 2 {
		t.Fatalf("two protectors expected: %+v", now)
	}
	if err := m.DeleteProtector(ctx, vol.ID, first); err != nil {
		t.Fatal(err)
	}
	now, err := m.Volume(ctx, letter)
	if err != nil || now == nil || len(now.Protectors) != 1 || now.Protectors[0] != second {
		t.Fatalf("after the removal: %+v %v", now, err)
	}
	if _, err := r.RecoveryPassword(ctx, vol.ID, first); err == nil {
		t.Fatal("a removed protector still gives its password")
	}
	if err := m.DeleteProtector(ctx, vol.ID, second); err != nil {
		t.Fatal(err)
	}
	// Still not encrypted: nothing here started encryption.
	if end, _ := m.Volume(ctx, letter); end == nil || end.Status != "decrypted" {
		t.Fatalf("the volume changed state: %+v", end)
	}
}
