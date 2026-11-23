package recovery

import (
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
		"EasyRMM agent silent when the wait ends":      {agentproto.TargetEasyRMMAgent, targetFacts{agentSeen: ago(AgentFresh + time.Minute)}, true, false},
	} {
		if got := c.f.back(c.target, now, done, c.waitOver); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}
