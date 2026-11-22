//go:build integration

package easypatch

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
)

// TestJobDetail checks a job in full: the device as EasyRMM and the engine
// know it, how the job started, and what the engine knows of its updates.
func TestJobDetail(t *testing.T) {
	f := newPatching(t)
	ctx := f.ctx
	security := eptest.NewUpdate("KB5070001 Security", "Security", "Missing")
	security["kbNumbers"], security["msrcSeverity"], security["knownExploited"], security["kevDueDate"] =
		[]string{"5070001"}, "Critical", true, "2026-12-01"
	security["cveIds"] = []string{"CVE-2026-1111", "CVE-2026-2222"}
	earlier := with(eptest.NewUpdate("KB5060001 Earlier", "Security", "Installed"), "kbNumbers", []string{"5060001"})
	gone := eptest.NewUpdate("KB5050001 Gone", "Security", "Missing")
	f.setUpdates(f.e1, security, earlier, gone)
	f.exec(`UPDATE devices SET os_description = 'Debian GNU/Linux 13 (trixie)', agent_version = '0.6.0' WHERE id = $1`, f.web)

	res, err := f.svc.Install(ctx, f.tech, InstallInput{DeviceIDs: []uuid.UUID{f.web},
		UpdateIDs: []uuid.UUID{guidOf(t, security), guidOf(t, earlier), guidOf(t, gone)}})
	if err != nil || res.Succeeded != 1 {
		t.Fatalf("install: %+v, %v", res, err)
	}
	job := *res.Results[0].JobID
	// One update installed since; another no longer offered.
	f.ep.Set(func() {
		f.e1.Updates = []map[string]any{security}
		f.e1.InstalledItems = []map[string]any{earlier}
	})

	// The job, as each refresh reads it: not the engine's lists of the
	// device's updates.
	lists := func() int {
		return len(f.ep.RequestsTo("GET", "/api/v1/endpoints/"+f.e1.ID.String()+"/updates")) +
			len(f.ep.RequestsTo("GET", "/api/v1/endpoints/"+f.e1.ID.String()+"/installed-updates"))
	}
	before := lists()
	d, err := f.svc.Job(ctx, f.tech, job)
	if err != nil || lists() != before {
		t.Fatalf("job: %d lists read, %v", lists()-before, err)
	}
	dev := d.Device
	if dev.OrganizationName != "Acme" || dev.SiteName != "HQ" || dev.OS != "Debian GNU/Linux 13 (trixie)" || dev.AgentVersion == nil ||
		*dev.AgentVersion != "0.6.0" || dev.Endpoint == nil || dev.Endpoint.Hostname != "web-01" || dev.Endpoint.OperatingSystem == "" {
		t.Fatalf("device: %+v %+v", dev, dev.Endpoint)
	}
	o := d.Origin
	if o == nil || o.Action != "patch.install" || o.By != "tess@example.com" || o.System || o.Updates == nil || *o.Updates != "3" ||
		o.PatchAll != nil || o.RequestID != nil {
		t.Fatalf("origin: %+v", o)
	}
	// What the engine knows of its updates, read once, apart.
	facts, err := f.svc.JobFacts(ctx, f.tech, job)
	if err != nil || len(d.Items) != 3 || facts.UpdateFactsError != nil || len(facts.UpdateFacts) != 2 || lists() != before+2 {
		t.Fatalf("items: %+v, facts %+v, %v, %v", d.Items, facts.UpdateFacts, facts.UpdateFactsError, err)
	}
	s := facts.UpdateFacts[guidOf(t, security)]
	if s.MsrcSeverity != "Critical" || !slices.Equal(s.KbNumbers, []string{"5070001"}) || len(s.CveIDs) != 2 || !s.KnownExploited ||
		s.KevDueDate != "2026-12-01" || s.SizeBytes == nil || s.Package == nil || s.State != "Missing" {
		t.Fatalf("security: %+v", s)
	}
	if e := facts.UpdateFacts[guidOf(t, earlier)]; e.State != "Installed" || len(e.CveIDs) != 1 {
		t.Fatalf("earlier: %+v", e)
	}
	if _, ok := facts.UpdateFacts[guidOf(t, gone)]; ok {
		t.Fatal("an update no longer listed has facts")
	}

	// The engine's lists cannot be read: what could be is kept, and the
	// error said; nor its endpoint.
	f.ep.Set(func() {
		f.ep.LoseReply = func(method, path string) bool {
			return method == "GET" && (strings.HasSuffix(path, "/installed-updates") || path == "/api/v1/endpoints/"+f.e1.ID.String())
		}
	})
	d, err = f.svc.Job(ctx, f.tech, job)
	if err != nil || d.Device.Endpoint != nil || d.Device.OS == "" {
		t.Fatalf("unread endpoint: %+v, %v", d.Device, err)
	}
	facts, err = f.svc.JobFacts(ctx, f.tech, job)
	if err != nil || facts.UpdateFactsError == nil || len(facts.UpdateFacts) != 1 {
		t.Fatalf("unread: %+v, %v, %v", facts.UpdateFacts, facts.UpdateFactsError, err)
	}
	f.ep.Set(func() { f.ep.LoseReply = nil })
	_, err = f.svc.JobFacts(ctx, f.outsider, job)
	wantErr(t, err, apperr.KindNotFound, "")

	// The record that started it is looked for near when the engine created
	// the job, not at any time since.
	f.ep.AgeJob(job, 10*time.Minute)
	if d, err = f.svc.Job(ctx, f.tech, job); err != nil || d.Origin == nil {
		t.Fatalf("ten minutes: %+v, %v", d.Origin, err)
	}
	f.ep.AgeJob(job, 2*time.Hour)
	if d, err = f.svc.Job(ctx, f.tech, job); err != nil || d.Origin != nil {
		t.Fatalf("two hours: %+v, %v", d.Origin, err)
	}

	// A retry names the job it runs again.
	f.ep.SetJobStatus(job, "Failed")
	retry, err := f.svc.RetryJob(ctx, f.tech, job)
	if err != nil {
		t.Fatal(err)
	}
	if d, err = f.svc.Job(ctx, f.tech, retry.ID); err != nil || d.Origin == nil || d.Origin.Action != "patch.retry" {
		t.Fatalf("retry: %+v, %v", d.Origin, err)
	}

	// Part of a Patch all.
	res, err = f.svc.Install(ctx, f.admin, InstallInput{All: true, OrganizationID: f.acme})
	if err != nil {
		t.Fatal(err)
	}
	var all uuid.UUID
	for _, it := range res.Results {
		if it.DeviceID == f.web && it.JobID != nil {
			all = *it.JobID
		}
	}
	d, err = f.svc.Job(ctx, f.tech, all)
	if err != nil || d.Origin == nil || d.Origin.PatchAll == nil || *d.Origin.PatchAll != "Acme" || d.Origin.RequestID == nil ||
		d.Origin.By != "ada@example.com" || *d.Origin.Updates != "all eligible" {
		t.Fatalf("patch all: %+v, %v", d.Origin, err)
	}
}

// TestJobDetailOrigins checks the jobs EasyRMM did not start, and the
// restart it asks for after an install.
func TestJobDetailOrigins(t *testing.T) {
	f := newPatching(t)
	ctx := f.ctx
	// A job the engine started on its own, canceled from EasyRMM: the
	// cancellation names it but did not start it.
	own := f.ep.AddJob(f.e1.ID, "UpdateScan", "Scheduled")
	if _, err := f.svc.CancelJob(ctx, f.tech, own); err != nil {
		t.Fatal(err)
	}
	d, err := f.svc.Job(ctx, f.tech, own)
	if err != nil || d.Origin != nil {
		t.Fatalf("engine's own: %+v, %v", d.Origin, err)
	}
	if facts, err := f.svc.JobFacts(ctx, f.tech, own); err != nil || len(facts.UpdateFacts) != 0 || facts.UpdateFactsError != nil {
		t.Fatalf("engine's own facts: %+v, %v", facts, err)
	}

	// The restart after an install: EasyRMM's own.
	install := f.installWithRestart(AfterInstall{Condition: conditionAlways})
	f.ep.SetJobStatus(install, "Completed")
	f.sweep(f.svc)
	restarts := f.restartJobs()
	if len(restarts) != 1 {
		t.Fatalf("restarts: %+v", restarts)
	}
	d, err = f.svc.Job(ctx, f.tech, restarts[0].ID)
	if err != nil || d.Origin == nil || !d.Origin.System || d.Origin.Action != "patch.restart" || d.RestartFor == nil || *d.RestartFor != install {
		t.Fatalf("restart: %+v, %v", d.Origin, err)
	}
}
