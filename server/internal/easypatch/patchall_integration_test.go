//go:build integration

package easypatch

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Patch all, every available update and restarts after installs (ADR-0030,
// amended 2026-11-22), on the patching engine as eptest, the stand-in,
// serves it.

func skipped(v ScopeView) map[string]int {
	out := map[string]int{}
	for _, s := range v.Skipped {
		out[s.Reason] = s.Count
	}
	return out
}

func TestPatchScope(t *testing.T) {
	f := newPatching(t)
	ctx := f.ctx

	// Everything the admin sees: web-01 and db-01 can be patched; lab-01 has
	// no agent, and app-01's agent is not linked.
	v, err := f.svc.Scope(ctx, f.admin, ScopeQuery{OrganizationID: f.acme})
	if err != nil || v.Devices != 2 || v.OrganizationName != "Acme" || v.SiteID != nil || !v.CanManage ||
		!slices.Equal(v.ByPlatform, []PlatformCount{{"linux", 2}}) || !maps(skipped(v), map[string]int{SkipNoAgent: 1, SkipNotLinked: 1}) {
		t.Fatalf("admin scope: %+v, %v", v, err)
	}
	// A site.
	v, err = f.svc.Scope(ctx, f.admin, ScopeQuery{OrganizationID: f.acme, SiteID: f.branch})
	if err != nil || v.Devices != 1 || v.SiteName != "Branch" || *v.SiteID != f.branch || len(v.Skipped) != 0 || v.where() != "Acme / Branch" {
		t.Fatalf("site scope: %+v, %v", v, err)
	}

	// A technician of one site sees that site's devices only, and no
	// other site.
	v, err = f.svc.Scope(ctx, f.tech, ScopeQuery{OrganizationID: f.acme})
	if err != nil || v.Devices != 1 || !v.CanManage || !maps(skipped(v), map[string]int{SkipNoAgent: 1, SkipNotLinked: 1}) {
		t.Fatalf("technician scope: %+v, %v", v, err)
	}
	_, err = f.svc.Scope(ctx, f.tech, ScopeQuery{OrganizationID: f.acme, SiteID: f.branch})
	wantErr(t, err, apperr.KindNotFound, "")
	_, err = f.svc.Scope(ctx, f.outsider, ScopeQuery{OrganizationID: f.acme})
	wantErr(t, err, apperr.KindNotFound, "")
	_, err = f.svc.Scope(ctx, f.admin, ScopeQuery{OrganizationID: uuid.New()})
	wantErr(t, err, apperr.KindNotFound, "")
	_, err = f.svc.Scope(ctx, f.admin, ScopeQuery{OrganizationID: f.acme, SiteID: uuid.New()})
	wantErr(t, err, apperr.KindNotFound, "")
	_, err = f.svc.Scope(ctx, f.admin, ScopeQuery{})
	wantField(t, err, "organizationId", "Choose an organization")
	_, err = f.svc.Scope(ctx, f.admin, ScopeQuery{OrganizationID: f.acme, SiteID: f.plant})
	wantField(t, err, "siteId", "site of the organization")
	_, err = f.svc.Scope(ctx, f.admin, ScopeQuery{OrganizationID: f.globex})
	wantErr(t, err, apperr.KindConflict, "easypatch_not_linked")
	_, err = f.withoutEngine().svc.Scope(ctx, f.admin, ScopeQuery{OrganizationID: f.acme})
	wantErr(t, err, apperr.KindConflict, "easypatch_not_configured")
}

func TestPatchScopeViewerAndStopped(t *testing.T) {
	f := newPatching(t)
	ctx := f.ctx
	// One who only views: every device is one they may not patch.
	v, err := f.svc.Scope(ctx, f.viewer, ScopeQuery{OrganizationID: f.acme})
	if err != nil || v.Devices != 0 || v.CanManage || !maps(skipped(v), map[string]int{SkipNotPermitted: 4}) {
		t.Fatalf("viewer scope: %+v, %v", v, err)
	}
	_, err = f.svc.Install(ctx, f.viewer, InstallInput{All: true, OrganizationID: f.acme})
	wantErr(t, err, apperr.KindForbidden, "")
	_, err = f.svc.Restart(ctx, f.viewer, RestartInput{Targets: Targets{All: true, OrganizationID: f.acme}})
	wantErr(t, err, apperr.KindForbidden, "")

	// Patching stopped on db-01.
	f.exec(`INSERT INTO easypatch_opt_outs (device_id) VALUES ($1)`, f.db)
	v, err = f.svc.Scope(ctx, f.admin, ScopeQuery{OrganizationID: f.acme})
	if err != nil || v.Devices != 1 || !maps(skipped(v), map[string]int{SkipStopped: 1, SkipNoAgent: 1, SkipNotLinked: 1}) ||
		v.Skipped[0].Reason != SkipStopped {
		t.Fatalf("stopped: %+v, %v", v, err)
	}
}

func maps(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestPatchAllInstall(t *testing.T) {
	f := newPatching(t)
	ctx := f.ctx

	// The selector's fields go together.
	_, err := f.svc.Install(ctx, f.admin, InstallInput{All: true, OrganizationID: f.acme, DeviceIDs: []uuid.UUID{f.web}})
	wantField(t, err, "deviceIds", "not both")
	_, err = f.svc.Install(ctx, f.admin, InstallInput{DeviceIDs: []uuid.UUID{f.web}, OrganizationID: f.acme})
	wantField(t, err, "all", "every device of the scope")
	_, err = f.svc.Install(ctx, f.admin, InstallInput{All: true})
	wantField(t, err, "organizationId", "Choose an organization")
	_, err = f.svc.Install(ctx, f.admin, InstallInput{All: true, OrganizationID: f.acme, Platforms: []string{"amiga"}})
	wantField(t, err, "platforms", "Choose Windows")
	_, err = f.svc.Install(ctx, f.admin, InstallInput{All: true, OrganizationID: f.acme, Platforms: []string{}})
	wantField(t, err, "platforms", "at least one platform")
	_, err = f.svc.Install(ctx, f.admin, InstallInput{All: true, OrganizationID: f.acme, Platforms: []string{"windows"}})
	wantErr(t, err, apperr.KindConflict, "easypatch_no_devices")
	_, err = f.svc.Install(ctx, f.admin, InstallInput{All: true, OrganizationID: f.acme, UpdateIDs: []uuid.UUID{uuid.New()}})
	wantField(t, err, "updateIds", "one device at a time")
	_, err = f.svc.Install(ctx, f.admin, InstallInput{DeviceIDs: []uuid.UUID{f.web}, Updates: "some"})
	wantField(t, err, "updates", "Choose the updates")
	_, err = f.svc.Install(ctx, f.admin, InstallInput{DeviceIDs: []uuid.UUID{f.web}, Features: true})
	wantField(t, err, "features", "every available update")
	_, err = f.svc.Install(ctx, f.admin, InstallInput{DeviceIDs: []uuid.UUID{f.web}, Updates: UpdatesAvailable,
		UpdateIDs: []uuid.UUID{uuid.New()}})
	wantField(t, err, "updateIds", "not both")

	// The technician's Patch all of Acme reaches their site's linked
	// device; db-01, at another site, is not theirs.
	later := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	res, err := f.svc.Install(ctx, f.tech, InstallInput{All: true, OrganizationID: f.acme, ScheduledAt: &later})
	if err != nil || res.Succeeded != 1 || res.Failed != 0 || res.Scope == nil || res.Scope.Devices != 1 || len(res.Batches) != 1 ||
		res.Batches[0] != (Batch{Devices: 1, Sent: 1}) || res.Results[0].DeviceID != f.web {
		t.Fatalf("technician's patch all: %+v, %v", res, err)
	}
	reqs := f.ep.RequestsTo("POST", "/api/v1/endpoints/bulk/install-updates")
	if len(reqs) != 1 || fmt.Sprint(reqs[0].Body["endpointIds"]) != fmt.Sprint([]any{f.e1.ID.String()}) ||
		reqs[0].Body["scheduledAt"] != later.Format(time.RFC3339) || reqs[0].Statement.Name != "tess@example.com" {
		t.Fatalf("bulk install: %+v", reqs)
	}
	per := f.audits("patch.install")
	if len(per) != 2 || per[0].Action != "patch.install" || per[0].Details["patchAll"] != "Acme" || per[0].Details["requestId"] == nil ||
		per[1].Action != "patch.install_all" || per[1].Details["requestId"] != per[0].Details["requestId"] ||
		per[1].Details["devices"] != float64(1) || per[1].Details["platforms"] != "every platform" ||
		fmt.Sprint(per[1].Details["skipped"]) != "map[no_agent:1 not_linked:1]" || per[1].Details["scheduledAt"] != later.Format(time.RFC3339) {
		t.Fatalf("audit: %+v", per)
	}

	// The admin's, of one site, on Linux.
	res, err = f.svc.Install(ctx, f.admin, InstallInput{All: true, OrganizationID: f.acme, SiteID: f.branch, Platforms: []string{"linux"}})
	if err != nil || res.Succeeded != 1 || res.Results[0].DeviceID != f.db || res.Scope.SiteName != "Branch" {
		t.Fatalf("site patch all: %+v, %v", res, err)
	}
	if got := f.audits("patch.install_all"); len(got) != 2 || got[1].Details["site"] != "Branch" || got[1].Details["platforms"] != "linux" {
		t.Fatalf("site audit: %+v", got)
	}
}

// TestPatchAllBatches has an organization larger than one request to the
// engine takes: it is sent whole, in batches, and a batch the engine does
// not take is reported while the next still goes.
func TestPatchAllBatches(t *testing.T) {
	f := newPatching(t)
	ctx := f.ctx
	const n = MaxBulk + 2
	big := f.id(`INSERT INTO organizations (name) VALUES ('Initech') RETURNING id`)
	site := f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'Main') RETURNING id`, big)
	epBig := f.ep.Org("Initech Patch")
	f.linkOrg(big, epBig, "Initech Patch")
	endpoints := make([]string, 0, n)
	for i := range n {
		endpoints = append(endpoints, f.ep.AddEndpoint(epBig, fmt.Sprintf("pc-%04d", i), "", fmt.Sprintf("FP-%04d", i)).ID.String())
	}
	f.exec(`WITH d AS (
			INSERT INTO devices (organization_id, site_id, name, hostname, platform)
			SELECT $1, $2, 'pc-' || lpad(i::text, 4, '0'), 'pc-' || lpad(i::text, 4, '0'), 'windows' FROM generate_series(0, $3 - 1) i
			RETURNING id, name)
		INSERT INTO easypatch_devices (device_id, endpoint_id, state, checked_at, linked_at)
		SELECT d.id, (($4::text[])[substring(d.name from 4)::int + 1])::uuid, 'linked', now(), now() FROM d`, big, site, n, endpoints)

	v, err := f.svc.Scope(ctx, f.admin, ScopeQuery{OrganizationID: big})
	if err != nil || v.Devices != n || !slices.Equal(v.ByPlatform, []PlatformCount{{"windows", n}}) {
		t.Fatalf("scope: %d %+v, %v", v.Devices, v.ByPlatform, err)
	}

	// Limits that need each device read stop before anything is sent.
	_, err = f.svc.Install(ctx, f.admin, InstallInput{All: true, OrganizationID: big, Updates: UpdatesAvailable})
	wantField(t, err, "updates", "at most 1,000 devices")
	_, err = f.svc.PlanAvailable(ctx, f.admin, AvailableInput{Targets: Targets{All: true, OrganizationID: big}})
	wantField(t, err, "updates", "at most 1,000 devices")
	_, err = f.svc.Install(ctx, f.admin, InstallInput{All: true, OrganizationID: big, Restart: &AfterInstall{Condition: conditionAlways}})
	wantField(t, err, "restart", "at most 100 devices")
	_, err = f.svc.Install(ctx, f.admin, InstallInput{All: true, OrganizationID: big, Restart: &AfterInstall{Condition: conditionPending}})
	wantField(t, err, "restart", "at most 1,000 devices")
	_, err = f.svc.PlanRestart(ctx, f.admin, RestartPlanInput{Targets: Targets{All: true, OrganizationID: big}, Condition: conditionAlways})
	wantField(t, err, "condition", "at most 100 devices")
	_, err = f.svc.PlanRestart(ctx, f.admin, RestartPlanInput{Targets: Targets{All: true, OrganizationID: big}, AfterInstall: true})
	wantField(t, err, "restart", "at most 1,000 devices")
	if got := len(f.ep.RequestsTo("POST", "/api/v1/endpoints/bulk/install-updates")); got != 0 {
		t.Fatalf("sent %d", got)
	}

	// Batches of 200: the engine starts a bulk request's jobs one after
	// another. The first batch's reply is lost: it is reported as not
	// known, and the next batches still go.
	calls := 0
	f.ep.Set(func() {
		f.ep.LoseReply = func(method, path string) bool {
			if path != "/api/v1/endpoints/bulk/install-updates" {
				return false
			}
			calls++
			return calls == 1
		}
	})
	res, err := f.svc.Install(ctx, f.admin, InstallInput{All: true, OrganizationID: big})
	if err != nil || res.Succeeded != n-patchAllBatch || res.Failed != patchAllBatch || len(res.Results) != n || len(res.Batches) != 6 ||
		res.Batches[0].Devices != patchAllBatch || res.Batches[0].Sent != 0 || res.Batches[0].Error == "" || !res.Batches[0].Unknown ||
		res.Batches[1] != (Batch{Devices: patchAllBatch, Sent: patchAllBatch}) || res.Batches[5] != (Batch{Devices: 2, Sent: 2}) ||
		!strings.HasPrefix(res.Results[0].Message, "Not known") {
		t.Fatalf("batches: %d %d %+v, %v", res.Succeeded, res.Failed, res.Batches, err)
	}
	reqs := f.ep.RequestsTo("POST", "/api/v1/endpoints/bulk/install-updates")
	if len(reqs) != 6 || len(reqs[0].Body["endpointIds"].([]any)) != patchAllBatch || len(reqs[5].Body["endpointIds"].([]any)) != 2 {
		t.Fatalf("requests: %d", len(reqs))
	}
	all := f.audits("patch.install_all")
	if len(all) != 1 || all[0].Details["devices"] != float64(n) || all[0].Details["succeeded"] != float64(n-patchAllBatch) ||
		len(all[0].Details["batches"].([]any)) != 6 || all[0].Details["batches"].([]any)[0].(map[string]any)["unknown"] != true {
		t.Fatalf("audit: %+v", all)
	}

	// A batch the engine refuses says so.
	f.ep.Set(func() { f.ep.LoseReply, f.ep.ReadOnly = nil, true })
	res, err = f.svc.Install(ctx, f.admin, InstallInput{All: true, OrganizationID: big})
	if err != nil || res.Succeeded != 0 || len(res.Batches) != 6 || res.Batches[0].Unknown || !strings.HasPrefix(res.Results[0].Message, "Not sent") {
		t.Fatalf("refused: %d %+v, %v", res.Succeeded, res.Batches, err)
	}
	if all = f.audits("patch.install_all"); len(all) != 2 {
		t.Fatalf("audit: %+v", all)
	}
}

func TestRestartAll(t *testing.T) {
	f := newPatching(t)
	ctx := f.ctx
	f.ep.Set(func() { f.e1.RebootPending, f.e2.RebootPending, f.e2.IsServer = true, true, true })

	plan, err := f.svc.PlanRestart(ctx, f.admin, RestartPlanInput{Targets: Targets{All: true, OrganizationID: f.acme}})
	if err != nil || plan.Scope == nil || plan.Scope.Devices != 2 || len(plan.Devices) != 2 || !plan.Devices[0].Server {
		t.Fatalf("plan: %+v, %v", plan, err)
	}
	// A server not ticked by name is left out, not refused.
	res, err := f.svc.Restart(ctx, f.admin, RestartInput{Targets: Targets{All: true, OrganizationID: f.acme}})
	if err != nil || res.Succeeded != 1 || res.Failed != 1 || res.Results[0].DeviceID != f.db ||
		!strings.Contains(res.Results[0].Message, "not ticked") || len(res.Batches) != 1 || res.RestartAfter != nil {
		t.Fatalf("restart all: %+v, %v", res, err)
	}
	got := f.audits("patch.restart")
	if len(got) != 2 || got[0].Details["patchAll"] != "Acme" || got[1].Action != "patch.restart_all" || got[1].Details["serversLeftOut"] != float64(1) ||
		got[1].Details["restarted"] != float64(1) {
		t.Fatalf("audit: %+v", got)
	}
	// Ticked, it restarts.
	f.finishRestarts()
	res, err = f.svc.Restart(ctx, f.admin, RestartInput{Targets: Targets{All: true, OrganizationID: f.acme}, ConfirmServers: []uuid.UUID{f.db}})
	if err != nil || res.Succeeded != 2 {
		t.Fatalf("with the server: %+v, %v", res, err)
	}
	// Nothing pending: nothing is sent, and that is no failure.
	f.ep.Set(func() { f.e1.RebootPending, f.e2.RebootPending = false, false })
	res, err = f.svc.Restart(ctx, f.admin, RestartInput{Targets: Targets{All: true, OrganizationID: f.acme, SiteID: f.hq}})
	if err != nil || res.Succeeded != 0 || res.Failed != 1 || len(res.Batches) != 0 {
		t.Fatalf("nothing pending: %+v, %v", res, err)
	}
	_, err = f.svc.Restart(ctx, f.admin, RestartInput{Targets: Targets{DeviceIDs: []uuid.UUID{f.web}, SiteID: f.hq}})
	wantField(t, err, "all", "every device of the scope")
	_, err = f.svc.PlanRestart(ctx, f.admin, RestartPlanInput{Targets: Targets{DeviceIDs: []uuid.UUID{f.web}, Platforms: []string{"linux"}}})
	wantField(t, err, "all", "every device of the scope")
	_, err = f.svc.PlanRestart(ctx, f.tech, RestartPlanInput{Targets: Targets{All: true, OrganizationID: f.acme, SiteID: f.branch}})
	wantErr(t, err, apperr.KindNotFound, "")
}

// setUpdates gives an endpoint its updates.
func (f *patchingFixture) setUpdates(e *eptest.Endpoint, updates ...map[string]any) {
	f.ep.Set(func() { e.Updates = updates })
}

func with(u map[string]any, k string, v any) map[string]any {
	u[k] = v
	return u
}

func TestInstallAvailable(t *testing.T) {
	f := newPatching(t)
	ctx := f.ctx
	soon := time.Now().Add(72 * time.Hour).UTC().Format(time.RFC3339)
	security := eptest.NewUpdate("KB5070001 Security", "Security", "Missing")
	failed := eptest.NewUpdate("KB5070002 Other", "Other", "Failed")
	delayed := with(eptest.NewUpdate("KB5070003 Cumulative", "Cumulative", "Missing"), "deferredUntil", soon)
	driver := eptest.NewUpdate("KB5070004 Driver", "Driver", "Missing")
	feature := eptest.NewUpdate("Windows 11 25H2", "Feature", "Missing")
	app := eptest.NewUpdate("Some.App 2.0", "Application", "Missing")
	excluded := with(eptest.NewUpdate("KB5070005 Excluded", "Security", "Missing"), "isExcluded", true)
	held := with(eptest.NewUpdate("KB5070006 Held", "Security", "Missing"), "holdReason", "Rollout guard")
	f.setUpdates(f.e1, security, failed, delayed, driver, feature, app, excluded, held,
		eptest.NewUpdate("KB5070007 Waiting", "Security", "PendingReboot"), eptest.NewUpdate("KB5070008 Again", "Security", "Reoffered"))
	f.setUpdates(f.e2)

	plan, err := f.svc.PlanAvailable(ctx, f.admin, AvailableInput{Targets: Targets{DeviceIDs: []uuid.UUID{f.web, f.db, f.lab}}})
	if err != nil || plan.Devices != 1 || plan.Updates != 4 || plan.UpToDate != 1 || plan.Features != 1 || plan.Held != 1 ||
		plan.NotApproved != 1 || plan.Deferred != 1 || plan.Excluded.Count != 1 ||
		!slices.Equal(plan.Excluded.Devices, []DeviceCount{{f.web, "web-01", 1}}) || len(plan.Errors) != 1 || plan.Errors[0].DeviceID != f.lab ||
		len(plan.Categories) != 4 || plan.Scope != nil {
		t.Fatalf("plan: %+v, %v", plan, err)
	}
	if plan, err = f.svc.PlanAvailable(ctx, f.admin, AvailableInput{Targets: Targets{All: true, OrganizationID: f.acme}, Features: true}); err != nil ||
		plan.Updates != 5 || plan.Features != 1 || plan.Scope == nil || plan.Scope.Devices != 2 {
		t.Fatalf("plan with features: %+v, %v", plan, err)
	}
	_, err = f.svc.PlanAvailable(ctx, f.viewer, AvailableInput{Targets: Targets{All: true, OrganizationID: f.acme}})
	wantErr(t, err, apperr.KindForbidden, "")
	_, err = f.svc.PlanAvailable(ctx, f.admin, AvailableInput{Targets: Targets{DeviceIDs: []uuid.UUID{f.web}, OrganizationID: f.acme}})
	wantField(t, err, "all", "every device")
	_, err = f.withoutEngine().svc.PlanAvailable(ctx, f.admin, AvailableInput{Targets: Targets{DeviceIDs: []uuid.UUID{f.web}}})
	wantErr(t, err, apperr.KindConflict, "easypatch_not_configured")
}

func TestInstallAvailableSends(t *testing.T) {
	f := newPatching(t)
	ctx := f.ctx
	security := eptest.NewUpdate("KB5070001 Security", "Security", "Missing")
	feature := eptest.NewUpdate("Windows 11 25H2", "Feature", "Missing")
	excluded := with(eptest.NewUpdate("KB5070005 Excluded", "Security", "Missing"), "isExcluded", true)
	f.setUpdates(f.e1, security, feature, excluded)
	f.setUpdates(f.e2)

	res, err := f.svc.Install(ctx, f.tech, InstallInput{DeviceIDs: []uuid.UUID{f.web}, Updates: UpdatesAvailable})
	if err != nil || res.Succeeded != 1 || res.Results[0].JobID == nil {
		t.Fatalf("install: %+v, %v", res, err)
	}
	reqs := f.ep.RequestsTo("POST", "/api/v1/endpoints/"+f.e1.ID.String()+"/install-updates")
	if len(reqs) != 1 || reqs[0].Body["mode"] != "Selected" ||
		fmt.Sprint(reqs[0].Body["updateGuids"]) != fmt.Sprint([]any{guidOf(t, security).String()}) {
		t.Fatalf("request: %+v", reqs)
	}
	// Feature upgrades when asked for; the whole organization, where db-01
	// has nothing to install.
	res, err = f.svc.Install(ctx, f.admin, InstallInput{All: true, OrganizationID: f.acme, Updates: UpdatesAvailable, Features: true})
	if err != nil || res.Succeeded != 1 || res.UpToDate != 1 || res.Results[0].DeviceID != f.db || res.Results[0].JobID != nil ||
		!res.Results[0].UpToDate || !strings.Contains(res.Results[0].Message, "Already up to date") || res.Results[1].JobID == nil ||
		len(res.Batches) != 0 {
		t.Fatalf("all: %+v, %v", res, err)
	}
	reqs = f.ep.RequestsTo("POST", "/api/v1/endpoints/"+f.e1.ID.String()+"/install-updates")
	if len(reqs) != 2 || len(reqs[1].Body["updateGuids"].([]any)) != 2 {
		t.Fatalf("with features: %+v", reqs)
	}
	got := f.audits("patch.install")
	if len(got) != 3 || got[0].Details["updates"] != "all available" || got[0].Details["updateCount"] != float64(1) ||
		got[2].Action != "patch.install_all" || got[2].Details["featureUpgrades"] != true || got[2].Details["upToDate"] != float64(1) ||
		got[2].Details["succeeded"] != float64(1) {
		t.Fatalf("audit: %+v", got)
	}

	// A device whose updates cannot be read, and one the engine refuses.
	f.ep.RemoveEndpoint(f.e2.ID)
	f.ep.Set(func() { f.e1.Missing = 0 })
	res, err = f.svc.Install(ctx, f.admin, InstallInput{DeviceIDs: []uuid.UUID{f.web, f.db}, Updates: UpdatesAvailable})
	if err != nil || res.Failed != 2 || !strings.Contains(res.Results[0].Message, "no eligible updates") ||
		!strings.Contains(res.Results[1].Message, "could not be read") {
		t.Fatalf("errors: %+v, %v", res, err)
	}
}

// restartRowOf reads an install's restart afterwards.
func (f *patchingFixture) restartRowOf(job uuid.UUID) (state, message string, restart, midway *uuid.UUID, claimed bool) {
	f.t.Helper()
	err := f.fixture.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT state, message, restart_job_id, midway_job_id, claimed_at IS NOT NULL
			FROM easypatch_install_restarts WHERE install_job_id = $1`, job).Scan(&state, &message, &restart, &midway, &claimed)
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return
}

// restartJobs lists the restarts the engine was asked for, oldest first.
func (f *patchingFixture) restartJobs() []eptest.Job {
	var out []eptest.Job
	for _, j := range f.ep.Jobs() {
		if j.Type == "Restart" {
			out = append(out, j)
		}
	}
	return out
}

// finishRestarts has the devices run the restarts asked of them: the
// engine refuses another restart of a device while one is queued or
// running (eptest's duplicate guard, as JobService.CreateAsync).
func (f *patchingFixture) finishRestarts() {
	for _, j := range f.restartJobs() {
		if active(j.Status) {
			f.ep.SetJobStatus(j.ID, "Completed")
		}
	}
}

func (f *patchingFixture) sweep(svc *Service) int {
	f.t.Helper()
	n, err := svc.SweepRestarts(f.ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	return n
}

// installWithRestart installs on web-01, restarting it afterwards as asked.
func (f *patchingFixture) installWithRestart(a AfterInstall, confirm ...uuid.UUID) uuid.UUID {
	f.t.Helper()
	res, err := f.svc.Install(f.ctx, f.tech, InstallInput{DeviceIDs: []uuid.UUID{f.web}, Restart: &a, ConfirmServers: confirm})
	if err != nil || res.Succeeded != 1 || res.RestartAfter == nil || *res.RestartAfter != 1 {
		f.t.Fatalf("install: %+v, %v", res, err)
	}
	return *res.Results[0].JobID
}

func TestRestartAfterInstall(t *testing.T) {
	f := newPatching(t)
	ctx := f.ctx

	// The choice is checked as any restart's.
	_, err := f.svc.Install(ctx, f.tech, InstallInput{DeviceIDs: []uuid.UUID{f.web}, Restart: &AfterInstall{Condition: "Sometimes"}})
	wantField(t, err, "restart", "Choose to restart")
	bad := 90
	_, err = f.svc.Install(ctx, f.tech, InstallInput{DeviceIDs: []uuid.UUID{f.web},
		Restart: &AfterInstall{Condition: conditionAlways, CountdownMinutes: &bad}})
	wantField(t, err, "countdownMinutes", "1 to 60")

	// A failed install never restarts its device.
	job := f.installWithRestart(AfterInstall{Condition: conditionAlways})
	if n := f.sweep(f.svc); n != 0 {
		t.Fatalf("while queued: %d", n)
	}
	if state, _, _, _, _ := f.restartRowOf(job); state != afterWaiting {
		t.Fatalf("queued: %s", state)
	}
	f.ep.SetJobStatus(job, "Failed")
	f.sweep(f.svc)
	if state, msg, restart, _, _ := f.restartRowOf(job); state != afterSkipped || !strings.Contains(msg, "failed") || restart != nil ||
		len(f.restartJobs()) != 0 {
		t.Fatalf("failed: %s %q %v", state, msg, restart)
	}
	for _, status := range []string{statusCanceled, "Expired"} {
		job = f.installWithRestart(AfterInstall{Condition: conditionAlways})
		f.ep.SetJobStatus(job, status)
		f.sweep(f.svc)
		if state, _, _, _, _ := f.restartRowOf(job); state != afterSkipped || len(f.restartJobs()) != 0 {
			t.Fatalf("%s: %s", status, state)
		}
	}

	// Completed: one restart, after the install, asked for once, as the
	// install asked, by EasyRMM on the technician's behalf.
	countdown := 10
	job = f.installWithRestart(AfterInstall{Condition: conditionAlways, Mode: "Countdown", CountdownMinutes: &countdown})
	f.ep.SetJobStatus(job, "Running")
	f.sweep(f.svc)
	f.ep.SetJobStatus(job, "Completed")
	if n := f.sweep(f.svc); n != 1 {
		t.Fatalf("asked %d", n)
	}
	f.sweep(f.svc)
	f.sweep(f.engineServiceWithClock(time.Now().Add(time.Hour)))
	restarts := f.restartJobs()
	state, _, restart, _, _ := f.restartRowOf(job)
	if len(restarts) != 1 || state != afterDone || restart == nil || *restart != restarts[0].ID || restarts[0].Endpoint != f.e1.ID {
		t.Fatalf("restart: %s %v %+v", state, restart, restarts)
	}
	reqs := f.ep.RequestsTo("POST", "/api/v1/endpoints/bulk/restart")
	if len(reqs) != 1 || reqs[0].Statement.Name != "tess@example.com" ||
		fmt.Sprint(reqs[0].Body["restart"]) != "map[condition:Always countdownMinutes:10 force:false mode:Countdown]" {
		t.Fatalf("request: %+v", reqs)
	}
	got := f.audits("patch.restart")
	if len(got) != 1 || got[0].Label != "patching" || got[0].Details["afterInstall"] != job.String() || got[0].Details["requestedBy"] != "tess@example.com" ||
		got[0].Details["jobId"] != restart.String() || got[0].Details["when"] != "when done" {
		t.Fatalf("audit: %+v", got)
	}
	if got := f.audits("patch.install"); got[len(got)-1].Details["restartAfter"] != "when done" ||
		got[len(got)-1].Details["restartMode"] != "after a 10-minute countdown" {
		t.Fatalf("install audit: %+v", got[len(got)-1])
	}

	// The job shows the choice and what became of it; the restart, the
	// install it follows.
	d, err := f.svc.Job(ctx, f.tech, job)
	if err != nil || d.RestartAfter == nil || d.RestartAfter.State != afterDone || *d.RestartAfter.RestartJobID != *restart ||
		d.RestartAfter.Condition != conditionAlways || *d.RestartAfter.CountdownMinutes != 10 || d.RestartAfter.RequestedBy != "tess@example.com" ||
		d.RestartFor != nil {
		t.Fatalf("install job: %+v, %v", d.RestartAfter, err)
	}
	if d, err = f.svc.Job(ctx, f.tech, *restart); err != nil || d.RestartAfter != nil || d.RestartFor == nil || *d.RestartFor != job {
		t.Fatalf("restart job: %+v, %v", d, err)
	}
	if d, err = f.svc.CancelJob(ctx, f.tech, *restart); err != nil || d.RestartFor == nil {
		t.Fatalf("cancel: %+v, %v", d, err)
	}
}

// engineServiceWithClock is another of EasyRMM's servers, or this one
// started again, whose clock reads now.
func (f *patchingFixture) engineServiceWithClock(now time.Time) *Service {
	svc := f.engineService(f.ep)
	svc.now = func() time.Time { return now }
	return svc
}

func TestRestartAfterInstallConditions(t *testing.T) {
	f := newPatching(t)

	// Only if the updates need it: they did not.
	job := f.installWithRestart(AfterInstall{Condition: conditionPending})
	f.ep.SetJobStatus(job, "Completed")
	f.sweep(f.svc)
	if state, msg, _, _, _ := f.restartRowOf(job); state != afterSkipped || !strings.Contains(msg, "did not need") || len(f.restartJobs()) != 0 {
		t.Fatalf("not needed: %s %q", state, msg)
	}
	// They did; the agent checks again when the restart runs.
	job = f.installWithRestart(AfterInstall{Condition: conditionPending})
	f.ep.SetJobRebootRequired(job, true)
	f.ep.SetJobStatus(job, "Completed")
	f.sweep(f.svc)
	reqs := f.ep.RequestsTo("POST", "/api/v1/endpoints/bulk/restart")
	if state, _, _, _, _ := f.restartRowOf(job); state != afterDone || len(reqs) != 1 ||
		reqs[0].Body["restart"].(map[string]any)["condition"] != conditionPending {
		t.Fatalf("needed: %s %+v", state, reqs)
	}

	// The install waits for a restart to go on: one restart then, and the
	// last when it has finished.
	f.finishRestarts()
	job = f.installWithRestart(AfterInstall{Condition: conditionAlways})
	f.ep.SetJobStatus(job, "WaitingForReboot")
	f.sweep(f.svc)
	f.sweep(f.svc)
	state, msg, restart, midway, _ := f.restartRowOf(job)
	if state != afterWaiting || midway == nil || restart != nil || !strings.Contains(msg, "goes on") || len(f.restartJobs()) != 2 {
		t.Fatalf("midway: %s %q %v %v", state, msg, restart, midway)
	}
	if reqs = f.ep.RequestsTo("POST", "/api/v1/endpoints/bulk/restart"); reqs[1].Body["restart"].(map[string]any)["condition"] != conditionPending {
		t.Fatalf("midway restart: %+v", reqs[1])
	}
	f.ep.SetJobStatus(*midway, "Completed")
	f.ep.SetJobStatus(job, "Completed")
	f.sweep(f.svc)
	state, _, restart, _, _ = f.restartRowOf(job)
	if state != afterDone || restart == nil || *restart == *midway || len(f.restartJobs()) != 3 {
		t.Fatalf("final: %s %v", state, restart)
	}
	if d, err := f.svc.Job(f.ctx, f.tech, *midway); err != nil || d.RestartFor == nil || *d.RestartFor != job {
		t.Fatalf("midway job: %+v, %v", d.RestartFor, err)
	}
	if got := f.audits("patch.restart"); len(got) != 3 || got[1].Details["when"] != "while the install waited for a restart" {
		t.Fatalf("audit: %+v", got)
	}
}

func TestRestartAfterInstallServersAndDevices(t *testing.T) {
	f := newPatching(t)

	// A server restarts only when ticked by name; unticked, it installs.
	f.ep.Set(func() { f.e1.IsServer = true })
	job := f.installWithRestart(AfterInstall{Condition: conditionAlways})
	f.ep.SetJobStatus(job, "Completed")
	f.sweep(f.svc)
	if state, msg, _, _, _ := f.restartRowOf(job); state != afterSkipped || !strings.Contains(msg, "not ticked by name: it installed") ||
		len(f.restartJobs()) != 0 {
		t.Fatalf("unticked: %s %q", state, msg)
	}
	job = f.installWithRestart(AfterInstall{Condition: conditionAlways})
	f.ep.SetJobStatus(job, "WaitingForReboot")
	f.sweep(f.svc)
	if state, msg, _, _, _ := f.restartRowOf(job); state != afterSkipped || !strings.Contains(msg, "waits for a restart") {
		t.Fatalf("unticked midway: %s %q", state, msg)
	}
	job = f.installWithRestart(AfterInstall{Condition: conditionAlways}, f.web)
	f.ep.SetJobStatus(job, "Completed")
	f.sweep(f.svc)
	if state, _, _, _, _ := f.restartRowOf(job); state != afterDone || len(f.restartJobs()) != 1 {
		t.Fatalf("ticked: %s", state)
	}
	if d, _ := f.svc.Job(f.ctx, f.tech, job); d.RestartAfter == nil || !d.RestartAfter.Server {
		t.Fatalf("ticked job: %+v", d.RestartAfter)
	}
	f.finishRestarts()

	// An agent that cannot restart, an endpoint the engine no longer has,
	// and an install it no longer has.
	f.ep.Set(func() { f.e1.IsServer, f.e1.CannotRestart = false, true })
	job = f.installWithRestart(AfterInstall{Condition: conditionAlways})
	f.ep.SetJobStatus(job, "Completed")
	f.sweep(f.svc)
	if state, msg, _, _, _ := f.restartRowOf(job); state != afterSkipped || !strings.Contains(msg, "cannot restart") {
		t.Fatalf("cannot restart: %s %q", state, msg)
	}
	f.ep.Set(func() { f.e1.CannotRestart = false })
	job = f.installWithRestart(AfterInstall{Condition: conditionAlways})
	f.exec(`UPDATE easypatch_install_restarts SET install_job_id = $2, install_job_ids = ARRAY[$2::uuid] WHERE install_job_id = $1`, job, uuid.Nil)
	f.sweep(f.svc)
	if state, msg, _, _, _ := f.restartRowOf(uuid.Nil); state != afterSkipped || !strings.Contains(msg, "no longer has the install") {
		t.Fatalf("no install: %s %q", state, msg)
	}

	// Patching stopped on the device.
	job = f.installWithRestart(AfterInstall{Condition: conditionAlways})
	f.ep.SetJobStatus(job, "Completed")
	f.exec(`INSERT INTO easypatch_opt_outs (device_id) VALUES ($1)`, f.web)
	f.sweep(f.svc)
	if state, msg, _, _, _ := f.restartRowOf(job); state != afterSkipped || !strings.Contains(msg, "stopped") {
		t.Fatalf("stopped: %s %q", state, msg)
	}
	f.exec(`DELETE FROM easypatch_opt_outs WHERE device_id = $1`, f.web)

	// The engine's endpoint is gone; then the device's agent changed.
	job = f.installWithRestart(AfterInstall{Condition: conditionAlways})
	f.ep.SetJobStatus(job, "Completed")
	f.exec(`UPDATE easypatch_install_restarts SET endpoint_id = $2 WHERE install_job_id = $1`, job, uuid.New())
	f.sweep(f.svc)
	if state, msg, _, _, _ := f.restartRowOf(job); state != afterSkipped || !strings.Contains(msg, "agent changed") {
		t.Fatalf("changed: %s %q", state, msg)
	}

	// An install left waiting past the limit.
	job = f.installWithRestart(AfterInstall{Condition: conditionAlways})
	f.sweep(f.engineServiceWithClock(time.Now().Add(41 * 24 * time.Hour)))
	if state, msg, _, _, _ := f.restartRowOf(job); state != afterSkipped || !strings.Contains(msg, "40 days") {
		t.Fatalf("too long: %s %q", state, msg)
	}

	// The engine refusing the restart.
	job = f.installWithRestart(AfterInstall{Condition: conditionAlways})
	f.ep.SetJobStatus(job, "Completed")
	f.ep.Set(func() { f.ep.ReadOnly = true })
	f.sweep(f.svc)
	if state, msg, _, _, _ := f.restartRowOf(job); state != afterFailed || !strings.Contains(msg, "refused") {
		t.Fatalf("refused: %s %q", state, msg)
	}
	f.ep.Set(func() { f.ep.ReadOnly = false })

	// The device deleted takes its restart with it.
	f.installWithRestart(AfterInstall{Condition: conditionAlways})
	f.exec(`DELETE FROM devices WHERE id = $1`, f.web)
	if n := f.sweep(f.svc); n != 0 {
		t.Fatalf("deleted: %d", n)
	}
}

// TestRestartAfterInstallSurvives checks that a restart of EasyRMM's server
// neither loses a restart after an install nor asks for it twice.
func TestRestartAfterInstallSurvives(t *testing.T) {
	f := newPatching(t)

	// The choice is kept: a server started afresh restarts the device.
	job := f.installWithRestart(AfterInstall{Condition: conditionAlways})
	f.ep.SetJobStatus(job, "Completed")
	if n := f.sweep(f.engineServiceWithClock(time.Now())); n != 1 || len(f.restartJobs()) != 1 {
		t.Fatalf("after a restart: %d", n)
	}

	// The engine took the restart but its answer was lost: the claim stays,
	// no server asks again while it may be in flight, and once it is stale
	// the restart found in the engine is adopted, not asked for again.
	f.finishRestarts()
	job = f.installWithRestart(AfterInstall{Condition: conditionAlways})
	f.ep.SetJobStatus(job, "Completed")
	f.ep.Set(func() { f.ep.LoseReply = func(_, path string) bool { return path == "/api/v1/endpoints/bulk/restart" } })
	if _, err := f.svc.SweepRestarts(f.ctx); err == nil {
		t.Fatal("a lost answer is an error")
	}
	f.ep.Set(func() { f.ep.LoseReply = nil })
	if state, _, _, _, claimed := f.restartRowOf(job); state != afterWaiting || !claimed || len(f.restartJobs()) != 2 {
		t.Fatalf("lost: %s %v", state, claimed)
	}
	f.sweep(f.engineServiceWithClock(time.Now()))
	if len(f.restartJobs()) != 2 {
		t.Fatal("asked again while in flight")
	}
	f.sweep(f.engineServiceWithClock(time.Now().Add(3 * time.Minute)))
	state, _, restart, _, claimed := f.restartRowOf(job)
	if restarts := f.restartJobs(); state != afterDone || claimed || len(restarts) != 2 || *restart != restarts[1].ID {
		t.Fatalf("adopted: %s %v %v", state, restart, claimed)
	}
	if got := f.audits("patch.restart"); len(got) != 2 || got[1].Details["jobId"] != restart.String() {
		t.Fatalf("audit: %+v", got)
	}

	// A server stopped after claiming, before asking: the engine has no
	// restart, so it is asked for, once.
	f.finishRestarts()
	job = f.installWithRestart(AfterInstall{Condition: conditionAlways})
	f.ep.SetJobStatus(job, "Completed")
	f.exec(`UPDATE easypatch_install_restarts SET claimed_at = now() - interval '5 minutes', claimed_for = 'final' WHERE install_job_id = $1`, job)
	f.sweep(f.engineServiceWithClock(time.Now()))
	f.sweep(f.engineServiceWithClock(time.Now()))
	if state, _, _, _, claimed := f.restartRowOf(job); state != afterDone || claimed || len(f.restartJobs()) != 3 {
		t.Fatalf("resent: %s %v %d", state, claimed, len(f.restartJobs()))
	}

	// The engine down: the pass says so, nothing changes, and the next
	// pass goes on.
	job = f.installWithRestart(AfterInstall{Condition: conditionAlways})
	f.ep.Set(func() { f.ep.Down = true })
	if _, err := f.svc.SweepRestarts(f.ctx); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("down: %v", err)
	}
	f.ep.Set(func() { f.ep.Down = false })
	if state, _, _, _, claimed := f.restartRowOf(job); state != afterWaiting || claimed {
		t.Fatalf("down: %s %v", state, claimed)
	}
	// Without the engine there is nothing to do.
	if n, err := f.unconfigured().SweepRestarts(f.ctx); n != 0 || err != nil {
		t.Fatalf("no engine: %d %v", n, err)
	}
}

// TestRestartAfterInstallPlan checks the plan the install dialog shows.
func TestRestartAfterInstallPlan(t *testing.T) {
	f := newPatching(t)
	f.ep.Set(func() { f.e2.IsServer = true })
	plan, err := f.svc.PlanRestart(f.ctx, f.admin, RestartPlanInput{Targets: Targets{DeviceIDs: []uuid.UUID{f.web, f.db, f.lab}}, AfterInstall: true})
	if err != nil || len(plan.Devices) != 3 || !plan.Devices[0].Restart || plan.Devices[0].Server || !plan.Devices[1].Server ||
		plan.Devices[2].Restart {
		t.Fatalf("plan: %+v, %v", plan, err)
	}
	f.ep.Set(func() { f.ep.Down = true })
	_, err = f.svc.PlanRestart(f.ctx, f.admin, RestartPlanInput{Targets: Targets{DeviceIDs: []uuid.UUID{f.web}}, AfterInstall: true})
	wantErr(t, err, apperr.KindUnavailable, "")
	f.ep.Set(func() { f.ep.Down = false })

	// More than one site's technician cannot reach the other.
	branchTech := f.user("bea@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.branch})
	res, err := f.svc.Install(f.ctx, branchTech, InstallInput{All: true, OrganizationID: f.acme})
	if err != nil || res.Succeeded != 1 || res.Results[0].DeviceID != f.db {
		t.Fatalf("branch technician: %+v, %v", res, err)
	}
}
