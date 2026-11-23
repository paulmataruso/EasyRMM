package easypatch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// repairSystem is a System that can also repair.
type repairSystem struct {
	*fakeSystem
	reinstalled []string // file name and contents
	reinstall   error
}

func (r *repairSystem) Service() string { return "easypatch-agent.test" }

func (r *repairSystem) Reinstall(_ context.Context, pkg agentproto.EasyPatchPackage, file string) error {
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	r.reinstalled = append(r.reinstalled, pkg.FileName, string(b))
	return r.reinstall
}

type restarts struct {
	names []string
	err   error
}

func (r *restarts) Restart(_ context.Context, name string) error {
	r.names = append(r.names, name)
	return r.err
}

func repairFixture(t *testing.T, version, status string) (*fixture, *repairSystem, *restarts) {
	t.Helper()
	f := newFixture(t, agentproto.EasyPatchDeb)
	sys := &repairSystem{fakeSystem: f.sys}
	svc := &restarts{}
	f.in.System, f.in.Services = sys, svc
	f.in.Present = func(context.Context) *agentproto.EasyPatchAgent {
		return &agentproto.EasyPatchAgent{Version: version, Status: status}
	}
	return f, sys, svc
}

func offered(f *fixture, version string) *agentproto.RepairEasyPatch {
	p := payload(f.now, agentproto.EasyPatchDeb)
	p.Packages[0].Version = version
	return &agentproto.RepairEasyPatch{Packages: p.Packages}
}

func TestRepairReinstallsTheSameVersionAndNeverInstallsOrEnrolls(t *testing.T) {
	f, sys, svc := repairFixture(t, "1.9.0", "Active")
	if err := f.in.Repair(t.Context(), t.Context(), offered(f, "1.9")); err != nil {
		t.Fatalf("repair: %v", err)
	}
	if len(sys.reinstalled) != 2 || sys.reinstalled[1] != string(testPackage) {
		t.Errorf("reinstalled %q", sys.reinstalled)
	}
	if len(sys.installed) != 0 || sys.enrolled != "" {
		t.Errorf("the install path ran: installed %q, enrolled %q", sys.installed, sys.enrolled)
	}
	if len(svc.names) != 1 || svc.names[0] != "easypatch-agent.test" {
		t.Errorf("restarts = %v", svc.names)
	}
	if f.finished != 1 {
		t.Errorf("inventory refreshed %d times", f.finished)
	}
	if left, _ := filepath.Glob(filepath.Join(f.in.Dir, "easypatch", "*")); len(left) != 0 {
		t.Errorf("left behind: %v", left)
	}
	if f.in.Busy() {
		t.Error("still busy")
	}
}

func TestRepairRefusals(t *testing.T) {
	tests := map[string]struct {
		version, status string
		offer           string
		download        []byte
		reinstall       error
		want            string
	}{
		"another version installed":     {"1.8.0", "Active", "1.9.0", testPackage, nil, "no package of version 1.8.0"},
		"an agent that is not enrolled": {"1.9.0", "NotEnrolled", "1.9.0", testPackage, nil, "not enrolled"},
		"a tampered package":            {"1.9.0", "Active", "1.9.0", []byte("something else"), nil, "bytes"},
		"the package manager fails":     {"1.9.0", "Active", "1.9.0", testPackage, errors.New("apt-get could not reinstall"), "could not reinstall"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			f, sys, svc := repairFixture(t, tt.version, tt.status)
			f.served = tt.download
			sys.reinstall = tt.reinstall
			err := f.in.Repair(t.Context(), t.Context(), offered(f, tt.offer))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
			if tt.reinstall == nil && len(sys.reinstalled) != 0 {
				t.Errorf("reinstalled %q", sys.reinstalled)
			}
			if len(svc.names) != 0 || len(sys.installed) != 0 || sys.enrolled != "" {
				t.Errorf("did more: restarts %v, installed %q, enrolled %q", svc.names, sys.installed, sys.enrolled)
			}
			if f.in.Busy() {
				t.Error("still busy after a failure")
			}
		})
	}
}

func TestRepairWithTheWrongHash(t *testing.T) {
	f, sys, _ := repairFixture(t, "1.9.0", "Active")
	r := offered(f, "1.9.0")
	sum := sha256.Sum256([]byte("another package"))
	r.Packages[0].SHA256 = hex.EncodeToString(sum[:])
	if err := f.in.Repair(t.Context(), t.Context(), r); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Errorf("error = %v", err)
	}
	if len(sys.reinstalled) != 0 {
		t.Error("reinstalled a package that does not match its hash")
	}
}

func TestRepairWhereTheAgentIsMissingTakesTheOfferedVersion(t *testing.T) {
	f, sys, _ := repairFixture(t, "", "")
	f.in.Present = func(context.Context) *agentproto.EasyPatchAgent { return nil }
	if err := f.in.Repair(t.Context(), t.Context(), offered(f, "1.9.0")); err != nil || len(sys.reinstalled) != 2 {
		t.Errorf("repair of a missing agent: %v, %q", err, sys.reinstalled)
	}
}

func TestRepairOnAMachineThatCannotRepair(t *testing.T) {
	f := newFixture(t, agentproto.EasyPatchDeb) // fakeSystem has no Reinstall
	if err := f.in.Repair(t.Context(), t.Context(), offered(f, "1.9.0")); err == nil || !strings.Contains(err.Error(), "cannot repair") {
		t.Errorf("repair: %v", err)
	}
	if err := f.in.Restart(t.Context()); err == nil {
		t.Error("restart accepted")
	}
	if err := f.in.Repair(t.Context(), t.Context(), nil); err == nil {
		t.Error("repair without a package accepted")
	}
}

func TestRepairHoldsInstallsBack(t *testing.T) {
	f, _, _ := repairFixture(t, "1.9.0", "Active")
	if err := f.in.claimRepair(); err != nil {
		t.Fatal(err)
	}
	if !f.in.Busy() {
		t.Error("a repair does not hold the agent busy")
	}
	if err := f.in.Repair(t.Context(), t.Context(), offered(f, "1.9.0")); err == nil {
		t.Error("two repairs at once")
	}
	f.in.releaseRepair()
	if f.in.Busy() {
		t.Error("busy after release")
	}
}

func TestRestart(t *testing.T) {
	f, _, svc := repairFixture(t, "1.9.0", "Active")
	if err := f.in.Restart(t.Context()); err != nil || len(svc.names) != 1 || svc.names[0] != "easypatch-agent.test" {
		t.Errorf("restart: %v, %v", err, svc.names)
	}
	svc.err = errors.New("access denied")
	if err := f.in.Restart(t.Context()); err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Errorf("failed restart: %v", err)
	}
	f.in.Present = func(context.Context) *agentproto.EasyPatchAgent { return nil }
	if err := f.in.Restart(t.Context()); err == nil || !strings.Contains(err.Error(), "needs a repair") {
		t.Errorf("restart of a missing agent: %v", err)
	}
}
