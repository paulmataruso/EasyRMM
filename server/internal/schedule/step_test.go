package schedule

import (
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/jobs"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

func TestStepCheck(t *testing.T) {
	sw := &jobs.Software{Action: jobs.ActionInstall, Manager: jobs.ManagerWinget, Package: "Mozilla.Firefox"}
	good := []struct {
		kind string
		st   Step
	}{
		{StepScript, Step{}},
		{StepSoftware, Step{Software: sw}},
		{StepRestart, Step{}},
		{StepRestart, Step{Platform: "windows"}},
		{StepShutdown, Step{Platform: "linux"}},
		{StepService, Step{Action: jobs.MaintServiceRestart, Service: "Spooler", Platform: "windows"}},
	}
	for _, c := range good {
		f := apperr.Fields{}
		c.st.check(f, c.kind)
		if err := f.Err(); err != nil {
			t.Errorf("%s %+v refused: %v", c.kind, c.st, err)
		}
	}
	bad := []struct {
		kind string
		st   Step
	}{
		{"nope", Step{}},
		{StepSoftware, Step{}},
		{StepSoftware, Step{Software: &jobs.Software{Action: "x", Manager: "y", Package: "z"}}},
		{StepRestart, Step{Platform: "mac"}},
		{StepService, Step{Action: jobs.MaintServiceStart, Service: "x"}},
		{StepService, Step{Action: jobs.MaintRestart, Service: "x", Platform: "linux"}},
		{StepService, Step{Action: jobs.MaintServiceStart, Service: "", Platform: "linux"}},
	}
	for _, c := range bad {
		f := apperr.Fields{}
		c.st.check(f, c.kind)
		if f.Err() == nil {
			t.Errorf("%s %+v accepted", c.kind, c.st)
		}
	}
}

// A step keeps only what its kind uses.
func TestStepCheckDropsStrays(t *testing.T) {
	st := Step{Service: "x", Platform: "linux", Action: "y"}
	st.check(apperr.Fields{}, StepRestart)
	if st != (Step{Platform: "linux"}) {
		t.Fatalf("restart step kept %+v", st)
	}
	st = Step{Service: "x"}
	st.check(apperr.Fields{}, StepScript)
	if st != (Step{}) {
		t.Fatalf("script step kept %+v", st)
	}
}

func TestStepPermissionsAndPlatforms(t *testing.T) {
	if (&Task{StepKind: StepSoftware}).perm() != rbac.PermSoftwareManage || (&Task{StepKind: StepRestart}).perm() != rbac.PermScriptRun {
		t.Error("permission by step")
	}
	if (&Task{StepKind: StepSoftware}).permVerb() != "manage software" || (&Task{StepKind: StepService}).permVerb() != "run scripts" {
		t.Error("verb by step")
	}
	both := (&Task{StepKind: StepRestart}).platforms(nil)
	if len(both) != 2 {
		t.Errorf("platforms %v", both)
	}
	if p := (&Task{StepKind: StepShutdown, Step: Step{Platform: "linux"}}).platforms(nil); len(p) != 1 || p[0] != "linux" {
		t.Errorf("platforms %v", p)
	}
	sw := &Task{StepKind: StepSoftware, Step: Step{Software: &jobs.Software{Manager: jobs.ManagerChocolatey}}}
	if p := sw.platforms(nil); len(p) != 1 || p[0] != "windows" {
		t.Errorf("software platforms %v", p)
	}
	m := Step{Action: jobs.MaintServiceStop, Service: "s"}.maintenance(StepService)
	if m.Action != jobs.MaintServiceStop || m.Service != "s" || (Step{}).maintenance(StepRestart).Action != jobs.MaintRestart || (Step{}).maintenance(StepShutdown).Action != jobs.MaintShutdown {
		t.Errorf("maintenance %+v", m)
	}
}
