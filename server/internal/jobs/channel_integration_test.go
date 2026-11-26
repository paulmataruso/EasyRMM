//go:build integration

package jobs

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// The channel's claim is the poll's claim: the same runs, marked sent; a
// claim over its budget is put back and left for the heartbeat's jobsWaiting
// and an ordinary poll; Waiting says what a poll would find.
func TestClaimForAndWaiting(t *testing.T) {
	f := newFixture(t)
	orgAdmin := f.user("orgadmin@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	sc, err := f.svc.CreateScript(f.ctx, orgAdmin, ScriptInput{OrganizationID: &f.acme, Name: "S", Shell: "sh", Body: strings.Repeat("x", 4000), TimeoutSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	pc := f.device(f.hq, "PC-01", "linux")
	var kicked []uuid.UUID
	f.svc.OnWork(func(ids []uuid.UUID) { kicked = append(kicked, ids...) })

	if w, err := f.svc.Waiting(f.ctx, pc); err != nil || w {
		t.Fatalf("waiting with nothing queued: %v %v", w, err)
	}
	job, err := f.svc.CreateJob(f.ctx, orgAdmin, JobInput{ScriptID: sc.ID, DeviceIDs: []uuid.UUID{pc}})
	if err != nil {
		t.Fatal(err)
	}
	if len(kicked) == 0 || kicked[0] != pc {
		t.Errorf("the channel was not told of the new run: %v", kicked)
	}
	if w, _ := f.svc.Waiting(f.ctx, pc); !w {
		t.Fatal("a queued run is not waiting")
	}

	// Over its budget: put back, and returned so that the caller can tell.
	resp, err := f.svc.ClaimFor(f.ctx, pc, 100)
	if err != nil || len(resp.Jobs) != 1 {
		t.Fatalf("claim %+v %v", resp, err)
	}
	if st := f.str(`SELECT status FROM job_runs WHERE id = $1`, job.Runs[0].ID); st != StatusQueued {
		t.Fatalf("an oversize claim left the run %s", st)
	}
	if n := f.str(`SELECT deliveries::text FROM job_runs WHERE id = $1`, job.Runs[0].ID); n != "0" {
		t.Errorf("deliveries %s", n)
	}
	if w, _ := f.svc.Waiting(f.ctx, pc); !w {
		t.Fatal("a run put back is not waiting")
	}

	// Within its budget: signed for this device, marked sent, not waiting.
	resp, err = f.svc.ClaimFor(f.ctx, pc, agentproto.MaxChannelBigFrame)
	if err != nil || len(resp.Jobs) != 1 {
		t.Fatalf("claim %+v %v", resp, err)
	}
	if _, err := agentproto.VerifyJob(f.key, resp.Jobs[0], pc.String(), time.Now()); err != nil {
		t.Fatalf("the claimed job does not verify: %v", err)
	}
	if st := f.str(`SELECT status FROM job_runs WHERE id = $1`, job.Runs[0].ID); st != StatusSent {
		t.Fatalf("the run is %s", st)
	}
	if w, _ := f.svc.Waiting(f.ctx, pc); w {
		t.Error("a run just sent is waiting")
	}
	if again, _ := f.svc.ClaimFor(f.ctx, pc, agentproto.MaxChannelBigFrame); len(again.Jobs) != 0 {
		t.Error("delivered twice at once")
	}
}
