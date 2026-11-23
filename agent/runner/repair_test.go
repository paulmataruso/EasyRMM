package runner

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// signedRepair returns the JSON of a repair instruction signed with the
// server's job key.
func signedRepair(t *testing.T, s *server, p agentproto.RepairPayload) string {
	t.Helper()
	if p.V == 0 {
		p.V = agentproto.RepairPayloadVersion
	}
	if p.DeviceID == "" {
		p.DeviceID = "dev-1"
	}
	if p.ExpiresAt.IsZero() {
		p.ExpiresAt = time.Now().Add(10 * time.Minute)
	}
	sr, err := agentproto.SignRepair(s.job, p)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(sr)
	return string(b)
}

// lastBeat returns the heartbeat request the server saw last.
func lastBeat(s *server) agentproto.HeartbeatRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.heartbeats[len(s.heartbeats)-1]
}

func TestHeartbeatCarriesMeshAgentState(t *testing.T) {
	s := &server{protocol: 2}
	m := &mesh{installed: true, running: true}
	r := newRunner(t, s, m)
	ctx := context.Background()
	// The first answer tells the level; until then the fields added after
	// level 2 are not sent (ADR-0009).
	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	if lastBeat(s).MeshAgent != nil {
		t.Error("state sent before the server's level was known")
	}
	m.stateErr = "start failed"
	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	got := lastBeat(s).MeshAgent
	if got == nil || !got.Installed || !got.Running || got.Host != "mesh.example.test:443" || got.Error != "start failed" {
		t.Errorf("state = %+v", got)
	}
}

func TestHeartbeatStateCarriesInstallFailure(t *testing.T) {
	s := &server{protocol: 2, available: true}
	m := &mesh{installErr: errors.New("disk full")}
	r := newRunner(t, s, m)
	ctx := context.Background()
	for range 3 { // level known, install fails, reported
		if _, err := r.beat(ctx); err != nil {
			t.Fatal(err)
		}
	}
	got := lastBeat(s).MeshAgent
	if got == nil || got.Error != "install failed: disk full" {
		t.Errorf("state = %+v", got)
	}
}

func TestRepairRestartsAndReportsOnce(t *testing.T) {
	s := &server{protocol: 2}
	m := &mesh{installed: true}
	r := newRunner(t, s, m)
	ctx := context.Background()
	s.repair = signedRepair(t, s, agentproto.RepairPayload{ID: "r1.0", Target: agentproto.TargetMeshAgent, Step: agentproto.StepRestart})
	for range 2 { // level, then the instruction
		if _, err := r.beat(ctx); err != nil {
			t.Fatal(err)
		}
	}
	r.repair.wait()
	// The instruction repeats until the server settles it: nothing runs twice.
	for range 2 {
		if _, err := r.beat(ctx); err != nil {
			t.Fatal(err)
		}
		r.repair.wait()
	}
	if m.restarts != 1 || m.repairs != 0 {
		t.Errorf("restarts %d, repairs %d", m.restarts, m.repairs)
	}
	if rep := lastBeat(s).Repair; rep == nil || rep.ID != "r1.0" || !rep.OK || rep.Error != "" {
		t.Errorf("report = %+v", rep)
	}
}

func TestRepairStepRewritesMeshAgent(t *testing.T) {
	s := &server{protocol: 2}
	m := &mesh{installed: true}
	r := newRunner(t, s, m)
	ctx := context.Background()
	s.repair = signedRepair(t, s, agentproto.RepairPayload{ID: "r1.1", Target: agentproto.TargetMeshAgent, Step: agentproto.StepRepair})
	for range 2 {
		if _, err := r.beat(ctx); err != nil {
			t.Fatal(err)
		}
	}
	r.repair.wait()
	if m.repairs != 1 || m.binary != "ELF" || m.settings != "MeshID=0x1" {
		t.Errorf("repairs %d, binary %q, settings %q", m.repairs, m.binary, m.settings)
	}
	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	if rep := lastBeat(s).Repair; rep == nil || !rep.OK {
		t.Errorf("report = %+v", rep)
	}
}

func TestRepairStepFailsWhenTheServerSignedNothingOrTheDownloadIsTampered(t *testing.T) {
	s := &server{protocol: 2, tamper: true}
	m := &mesh{installed: true}
	r := newRunner(t, s, m)
	ctx := context.Background()
	s.repair = signedRepair(t, s, agentproto.RepairPayload{ID: "r1.1", Target: agentproto.TargetMeshAgent, Step: agentproto.StepRepair})
	for range 3 {
		if _, err := r.beat(ctx); err != nil {
			t.Fatal(err)
		}
		r.repair.wait()
	}
	rep := lastBeat(s).Repair
	if rep == nil || rep.OK || !strings.Contains(rep.Error, "signature does not verify") {
		t.Errorf("report = %+v", rep)
	}
}

func TestRepairReportsAFailedRestart(t *testing.T) {
	s := &server{protocol: 2}
	m := &mesh{installed: true, restartErr: errors.New(strings.Repeat("x", 900))}
	r := newRunner(t, s, m)
	ctx := context.Background()
	s.repair = signedRepair(t, s, agentproto.RepairPayload{ID: "r2.0", Target: agentproto.TargetMeshAgent, Step: agentproto.StepRestart})
	for range 3 {
		if _, err := r.beat(ctx); err != nil {
			t.Fatal(err)
		}
		r.repair.wait()
	}
	rep := lastBeat(s).Repair
	if rep == nil || rep.OK || len(rep.Error) != agentproto.MaxRepairError {
		t.Errorf("report = %+v", rep)
	}
}

func TestRepairRefusals(t *testing.T) {
	good := agentproto.RepairPayload{ID: "r3.0", Target: agentproto.TargetMeshAgent, Step: agentproto.StepRestart}
	cases := map[string]func(*testing.T, *server) string{
		"another device": func(t *testing.T, s *server) string {
			p := good
			p.DeviceID = "dev-2"
			return signedRepair(t, s, p)
		},
		"expired": func(t *testing.T, s *server) string {
			p := good
			p.ExpiresAt = time.Now().Add(-time.Minute)
			return signedRepair(t, s, p)
		},
		"another key": func(t *testing.T, s *server) string {
			s2 := &server{}
			newRunner(t, s2, nil)
			return signedRepair(t, s2, good)
		},
		"unknown step": func(t *testing.T, s *server) string {
			p := good
			p.Step = "format"
			return signedRepair(t, s, p)
		},
		"garbage": func(*testing.T, *server) string { return `{"payload":"e30=","signature":"cw=="}` },
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			s := &server{protocol: 2}
			m := &mesh{installed: true}
			r := newRunner(t, s, m)
			s.repair = mk(t, s)
			for range 3 {
				if _, err := r.beat(context.Background()); err != nil {
					t.Fatal(err)
				}
				r.repair.wait()
			}
			if m.restarts != 0 || m.repairs != 0 || lastBeat(s).Repair != nil {
				t.Errorf("acted on it: restarts %d, repairs %d, report %+v", m.restarts, m.repairs, lastBeat(s).Repair)
			}
		})
	}
}

// A target this agent does not repair is reported, not ignored.
func TestRepairOfAnotherTargetIsReportedAsFailed(t *testing.T) {
	s := &server{protocol: 2}
	m := &mesh{installed: true}
	r := newRunner(t, s, m)
	s.repair = signedRepair(t, s, agentproto.RepairPayload{ID: "r4.0", Target: agentproto.TargetEasyPatchAgent, Step: agentproto.StepRestart})
	for range 3 {
		if _, err := r.beat(context.Background()); err != nil {
			t.Fatal(err)
		}
		r.repair.wait()
	}
	if rep := lastBeat(s).Repair; rep == nil || rep.OK || m.restarts != 0 {
		t.Errorf("report = %+v, restarts %d", rep, m.restarts)
	}
}

func TestRepairOutcomeIsKeptForAnHourOnly(t *testing.T) {
	var p repairs
	now := time.Now()
	p.finish(agentproto.RepairReport{ID: "x", OK: true}, now)
	if p.report(now.Add(time.Minute)) == nil {
		t.Error("outcome dropped at once")
	}
	if p.report(now.Add(agentproto.RepairReported)) != nil {
		t.Error("outcome kept past an hour")
	}
	if !p.begin("y") || p.begin("z") || p.begin("x") {
		t.Error("begin allowed two steps at once, or one done again")
	}
}
