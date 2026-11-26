package recovery

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

func TestWaitsDependOnTheTargetAndWhoAskedForTheRepair(t *testing.T) {
	for _, c := range []struct {
		target, trigger string
		want            time.Duration
	}{
		{agentproto.TargetMeshAgent, TriggerManual, 2 * time.Minute},
		{agentproto.TargetEasyPatchAgent, TriggerManual, 7 * time.Minute},
		{agentproto.TargetMeshAgent, TriggerAutomatic, 20 * time.Minute},
		{agentproto.TargetEasyPatchAgent, TriggerAutomatic, 30 * time.Minute},
	} {
		if got := waitFor(c.target, c.trigger); got != c.want {
			t.Errorf("waitFor(%s, %s) = %v, want %v", c.target, c.trigger, got, c.want)
		}
	}
	if maxRunning(TriggerManual) != time.Hour || maxRunning(TriggerAutomatic) != 2*time.Hour {
		t.Error("how long a repair may run")
	}
	// A repair outlasts its steps and waits.
	if 15*time.Minute+AutoWaitPatching+15*time.Minute+AutoWaitPatching >= maxRunning(TriggerAutomatic) {
		t.Error("an automatic repair of the EasyPatch agent cannot finish in the time it is given")
	}
}

func TestWhoCarriesWhat(t *testing.T) {
	for target, want := range map[string]string{
		agentproto.TargetMeshAgent:      agentproto.TargetEasyRMMAgent,
		agentproto.TargetEasyPatchAgent: agentproto.TargetEasyRMMAgent,
		agentproto.TargetEasyRMMAgent:   agentproto.TargetEasyPatchAgent, // through the patching engine (slice R3)
		"anything else":                 "",
	} {
		if got := carriedBy(target); got != want {
			t.Errorf("carriedBy(%q) = %q, want %q", target, got, want)
		}
	}
	for target, want := range map[string]string{
		agentproto.TargetMeshAgent: "MeshAgent", agentproto.TargetEasyPatchAgent: "EasyPatch agent", agentproto.TargetEasyRMMAgent: "EasyRMM agent",
	} {
		if got := targetLabel(target); got != want {
			t.Errorf("targetLabel(%q) = %q", target, got)
		}
	}
}

func TestWhenATargetIsBack(t *testing.T) {
	now := time.Now()
	ago := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }
	done := ago(10 * time.Minute)
	for name, c := range map[string]struct {
		target   string
		f        targetFacts
		waitOver bool
		want     bool
	}{
		"MeshAgent connected since the step":           {agentproto.TargetMeshAgent, targetFacts{online: true, changedAt: ago(5 * time.Minute)}, false, true},
		"MeshAgent connected before the step":          {agentproto.TargetMeshAgent, targetFacts{online: true, changedAt: ago(time.Hour)}, false, false},
		"MeshAgent still connected when the wait ends": {agentproto.TargetMeshAgent, targetFacts{online: true, changedAt: ago(time.Hour)}, true, true},
		"MeshAgent not connected":                      {agentproto.TargetMeshAgent, targetFacts{changedAt: ago(5 * time.Minute)}, true, false},
		"EasyPatch agent never seen":                   {agentproto.TargetEasyPatchAgent, targetFacts{}, true, false},
		"EasyPatch agent checked in since the step":    {agentproto.TargetEasyPatchAgent, targetFacts{patchSeen: ago(2 * time.Minute)}, false, true},
		"EasyPatch agent checked in before the step":   {agentproto.TargetEasyPatchAgent, targetFacts{patchSeen: ago(30 * time.Minute)}, false, false},
		"EasyPatch agent recent when the wait ends":    {agentproto.TargetEasyPatchAgent, targetFacts{patchSeen: ago(SilentAfter - time.Minute)}, true, true},
		"EasyPatch agent silent when the wait ends":    {agentproto.TargetEasyPatchAgent, targetFacts{patchSeen: ago(SilentAfter + time.Minute)}, true, false},
		"EasyRMM agent never seen":                     {agentproto.TargetEasyRMMAgent, targetFacts{}, true, false},
		"EasyRMM agent checked in since the step":      {agentproto.TargetEasyRMMAgent, targetFacts{agentSeen: ago(2 * time.Minute)}, false, true},
		"EasyRMM agent checked in before the step":     {agentproto.TargetEasyRMMAgent, targetFacts{agentSeen: ago(30 * time.Minute)}, false, false},
		"EasyRMM agent recent when the wait ends":      {agentproto.TargetEasyRMMAgent, targetFacts{agentSeen: ago(AgentFresh - time.Minute)}, true, true},
		"EasyRMM agent silent when the wait ends":      {agentproto.TargetEasyRMMAgent, targetFacts{agentSeen: ago(20 * time.Minute)}, true, false},
	} {
		if got := c.f.back(c.target, now, done, c.waitOver); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}

// The decision table of the one Repair button (ADR-0069, amended 2026-11-26).
func TestDecideNamesTheRunningAgentThatRepairsWhatIsDown(t *testing.T) {
	const (
		rmm   = agentproto.TargetEasyRMMAgent
		mesh  = agentproto.TargetMeshAgent
		patch = agentproto.TargetEasyPatchAgent
	)
	// Everything runs; each case takes something down.
	all := Facts{Enrolled: true, RMMUp: true, MeshExpected: true, MeshUp: true, PatchExpected: true, PatchUp: true, HasKey: true, HasPatching: true}
	with := func(f func(*Facts)) Facts { c := all; f(&c); return c }
	type act = [2]string // target, carried by
	for name, c := range map[string]struct {
		f       Facts
		down    []string
		repairs []act
		later   []string
		refusal string
	}{
		"nothing down":               {f: all, refusal: RefuseNothingDown},
		"mesh down":                  {f: with(func(f *Facts) { f.MeshUp = false }), down: []string{mesh}, repairs: []act{{mesh, rmm}}},
		"patch down":                 {f: with(func(f *Facts) { f.PatchUp = false }), down: []string{patch}, repairs: []act{{patch, rmm}}},
		"mesh and patch down":        {f: with(func(f *Facts) { f.MeshUp, f.PatchUp = false, false }), down: []string{mesh, patch}, repairs: []act{{mesh, rmm}, {patch, rmm}}},
		"rmm down":                   {f: with(func(f *Facts) { f.RMMUp = false }), down: []string{rmm}, repairs: []act{{rmm, patch}}},
		"rmm and mesh down":          {f: with(func(f *Facts) { f.RMMUp, f.MeshUp = false, false }), down: []string{rmm, mesh}, repairs: []act{{rmm, patch}}, later: []string{mesh}},
		"rmm down, patch down":       {f: with(func(f *Facts) { f.RMMUp, f.PatchUp = false, false }), down: []string{rmm, patch}, refusal: RefuseNoRunning},
		"all down":                   {f: with(func(f *Facts) { f.RMMUp, f.MeshUp, f.PatchUp = false, false, false }), down: []string{rmm, mesh, patch}, refusal: RefuseNoRunning},
		"rmm down, no patching here": {f: with(func(f *Facts) { f.RMMUp, f.PatchExpected, f.PatchUp = false, false, false }), down: []string{rmm}, refusal: RefuseNoRunning},
		"no agent":                   {f: Facts{}, refusal: RefuseNoAgent},
		"leaving":                    {f: with(func(f *Facts) { f.MeshUp, f.Leaving = false, true }), refusal: RefuseLeaving},
		"no key":                     {f: with(func(f *Facts) { f.MeshUp, f.HasKey = false, false }), down: []string{mesh}, refusal: RefuseNoJobKey},
		"mesh running already":       {f: with(func(f *Facts) { f.MeshUp, f.Running = false, map[string]bool{mesh: true} }), down: []string{mesh}, refusal: RefuseRunning},
		"one of two running":         {f: with(func(f *Facts) { f.MeshUp, f.PatchUp, f.Running = false, false, map[string]bool{mesh: true} }), down: []string{mesh, patch}, repairs: []act{{patch, rmm}}},
	} {
		p := Decide(c.f)
		var got []act
		for _, a := range p.Repairs {
			got = append(got, act{a.Target, a.CarriedBy})
		}
		if !slices.Equal(p.Down, c.down) && (len(p.Down) != 0 || len(c.down) != 0) && c.refusal != RefuseLeaving && c.refusal != RefuseNoAgent && c.refusal != RefuseNoJobKey {
			t.Errorf("%s: down = %v, want %v", name, p.Down, c.down)
		}
		if !slices.Equal(got, c.repairs) || !slices.Equal(p.Later, c.later) || p.Refusal != c.refusal || p.Summary == "" {
			t.Errorf("%s: plan = %+v, want repairs %v later %v refusal %q", name, p, c.repairs, c.later, c.refusal)
		}
	}
	if s := Decide(with(func(f *Facts) { f.RMMUp, f.MeshUp = false, false })).Summary; !strings.Contains(s, "The EasyPatch agent will restart the EasyRMM agent") || !strings.Contains(s, "press Repair again") {
		t.Errorf("summary = %q", s)
	}
}
