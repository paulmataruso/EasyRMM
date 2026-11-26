package jobs

import "testing"

// A job's name holds 200 characters (the jobs table): a scan that asks for
// many modules gets their number, and a short list keeps its names.
func TestHardeningLabelFitsTheJobsTable(t *testing.T) {
	all := Hardening{Platform: HardeningWindows, Mode: HardeningCheck, Modules: WindowsHardeningModules[:len(WindowsHardeningModules)-1]}
	if l := all.windowsLabel(); len(l) > 200 || l != "Check Windows hardening: 29 modules" {
		t.Errorf("%q", l)
	}
	few := Hardening{Platform: HardeningWindows, Mode: HardeningCheck, Modules: []string{"rdp", "session"}}
	if l := few.windowsLabel(); l != "Check Windows hardening: rdp, session" {
		t.Errorf("%q", l)
	}
	lin := Hardening{Mode: HardeningCheck, Modules: HardeningModules[:len(HardeningModules)-1]}
	if l := lin.label(); len(l) > 200 {
		t.Errorf("%q", l)
	}
}
