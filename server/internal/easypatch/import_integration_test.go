//go:build integration

package easypatch

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
	"github.com/paulmataruso/easyrmm/server/internal/tenancy"
)

// TestImport: a standalone EasyPatch's organizations and sites, restored
// as the engine's, become EasyRMM's (one-product plan, phase S; ADR-0045).
func TestImport(t *testing.T) {
	f := newFixture(t)
	engine := eptest.NewEngine(t, reconcileKey)
	// The restored database: Acme as EasyRMM has it, in another time zone;
	// two organizations whose names differ only in case; one with a time
	// zone EasyRMM does not know; one archived.
	acme := engine.Org("Acme")
	engine.ChangeOrganization(acme, func(o *eptest.OrgInfo) { o.TimeZone = "Europe/Oslo" })
	hq, warehouse, hqLower, closed := engine.Site(acme, "HQ"), engine.Site(acme, "Warehouse"), engine.Site(acme, "hq"), engine.Site(acme, "Closed")
	engine.ChangeSite(closed, func(x *eptest.SiteInfo) { x.Active = false })
	address := "1 Harbor Road"
	engine.ChangeSite(warehouse, func(x *eptest.SiteInfo) { x.Address = &address })
	engine.ChangeSite(hqLower, func(x *eptest.SiteInfo) { x.TimeZone = "Atlantis/Central" })
	fabrikam, fabrikamLower := engine.Org("Fabrikam"), engine.Org("fabrikam")
	mainSite := engine.Site(fabrikam, "Main")
	mars := engine.Org("Mars\tBase")
	engine.ChangeOrganization(mars, func(o *eptest.OrgInfo) { o.TimeZone = "Mars/Olympus" })
	old := engine.Org("Old")
	engine.ChangeOrganization(old, func(o *eptest.OrgInfo) { now := time.Now(); o.Active, o.ArchivedAt = false, &now })

	// Links to the engine the database replaced, and an opt-out, which is
	// EasyRMM's own.
	f.exec(`INSERT INTO easypatch_organizations (organization_id, easypatch_id, easypatch_name) VALUES ($1, $2, 'Globex')`, f.globex, uuid.New())
	f.exec(`INSERT INTO easypatch_forgotten (kind, easypatch_id, name) VALUES ('organization', $1, 'Gone')`, uuid.New())
	device := f.device(f.globex, f.plant, "kept-out")
	f.exec(`INSERT INTO easypatch_opt_outs (device_id) VALUES ($1)`, device)

	// Without the engine, nothing to import into.
	ten := tenancy.New(f.db, audit.New(f.db, nil))
	if _, err := f.unconfigured().Import(f.ctx, ten); !errors.Is(err, errImportNeedsEngine) {
		t.Fatalf("without the engine: %v", err)
	}

	// An engine that refuses EasyRMM: nothing changes.
	signer, _ := NewSigner([]byte(strings.Repeat("k", 32)))
	refused, err := NewEngineClient(engine.URL(), signer, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.UseEngine(refused); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Import(f.ctx, ten); err == nil || !strings.Contains(err.Error(), "reading the patching engine's organizations") ||
		f.count(`SELECT count(*) FROM easypatch_forgotten`) != 1 {
		t.Fatalf("refused: %v", err)
	}

	f.svc = f.engineService(engine)
	rep, err := f.svc.Import(f.ctx, ten)
	if err != nil {
		t.Fatal(err)
	}
	type rec struct {
		kind, engineName, org, name string
		joined                      bool
	}
	var got []rec
	ids := map[uuid.UUID]uuid.UUID{}
	for _, r := range rep.Records {
		got = append(got, rec{r.Kind, r.EngineName, r.Organization, r.Name, r.Joined})
		ids[r.EngineID] = r.ID
	}
	want := []rec{
		{"organization", "Acme", "", "Acme", true},
		{"site", "HQ", "Acme", "HQ", true},
		{"site", "Warehouse", "Acme", "Warehouse", false},
		{"site", "hq", "Acme", "hq (2)", false},
		{"organization", "Fabrikam", "", "Fabrikam", false},
		{"site", "Main", "Fabrikam", "Main", false},
		{"organization", "Mars\tBase", "", "Mars Base", false},
		{"organization", "fabrikam", "", "fabrikam (2)", false},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("records:\n got %+v\nwant %+v", got, want)
	}
	if rep.ArchivedOrganizations != 1 || rep.ArchivedSites != 1 {
		t.Fatalf("archived: %+v", rep)
	}
	if len(rep.Warnings) != 4 || !strings.Contains(rep.Warnings[0], `"Acme" joined EasyRMM's "Acme", whose time zone (UTC)`) ||
		!strings.Contains(rep.Warnings[1], `Site "HQ" of "Acme" joined EasyRMM's "HQ", whose time zone (UTC)`) ||
		!strings.Contains(rep.Warnings[2], `"Atlantis/Central" is not one EasyRMM knows`) ||
		!strings.Contains(rep.Warnings[3], `"Mars/Olympus" is not one EasyRMM knows`) {
		t.Fatalf("warnings: %q", rep.Warnings)
	}
	if j, c := rep.Count("organization"); j != 1 || c != 3 {
		t.Fatalf("organizations: %d joined, %d created", j, c)
	}
	if ids[acme] != f.acme || ids[hq] != f.hq || ids[warehouse] == uuid.Nil || ids[hqLower] == uuid.Nil || ids[mainSite] == uuid.Nil {
		t.Fatalf("ids: %v", ids)
	}

	// Linked, with automatic installs; the replaced engine's links are gone
	// and the opt-out stays.
	if f.engineOrg(f.acme) != acme || f.engineOrg(ids[fabrikamLower]) != fabrikamLower || f.engineSite(ids[hqLower]) != hqLower {
		t.Fatal("links")
	}
	if n := f.count(`SELECT count(*) FROM easypatch_organizations WHERE auto_install`); n != 4 {
		t.Fatalf("organization links: %d", n)
	}
	if f.count(`SELECT count(*) FROM easypatch_organizations WHERE organization_id = $1`, f.globex) != 0 ||
		f.count(`SELECT count(*) FROM easypatch_forgotten`) != 0 || f.count(`SELECT count(*) FROM easypatch_opt_outs`) != 1 {
		t.Fatal("cleared tables")
	}
	if n := f.count(`SELECT count(*) FROM organizations WHERE name = 'fabrikam (2)' AND timezone = 'UTC'`); n != 1 {
		t.Fatalf("new organization: %d", n)
	}
	if n := f.count(`SELECT count(*) FROM sites WHERE id = $1 AND timezone = 'Europe/Oslo' AND address = $2`, ids[warehouse], address); n != 1 {
		t.Fatalf("new site's time zone: %d", n)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'easypatch.import'`); n != 1 {
		t.Fatalf("audit: %d", n)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action IN ('easypatch.organization_import', 'easypatch.site_import')`); n != 8 {
		t.Fatalf("link audit: %d", n)
	}

	// Again: the same records, all found.
	orgs := f.count(`SELECT count(*) FROM organizations`)
	again, err := f.svc.Import(f.ctx, ten)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Records) != len(rep.Records) || f.count(`SELECT count(*) FROM organizations`) != orgs {
		t.Fatalf("again: %+v", again.Records)
	}
	for i, r := range again.Records {
		if !r.Joined || r.ID != rep.Records[i].ID {
			t.Fatalf("again, %s %q: %+v", r.Kind, r.EngineName, r)
		}
	}

	// The reconciler then keeps them as any other: the engine takes
	// EasyRMM's names and time zones, and EasyRMM's own organization.
	f.reconcile()
	byID := map[uuid.UUID]eptest.OrgInfo{}
	for _, o := range engine.Organizations() {
		byID[o.ID] = o
	}
	if byID[fabrikamLower].Name != "fabrikam (2)" || byID[acme].TimeZone != "UTC" || byID[mars].Name != "Mars Base" {
		t.Fatalf("engine after a pass: %+v", byID)
	}
	if f.count(`SELECT count(*) FROM easypatch_organizations WHERE organization_id = $1`, f.globex) != 1 {
		t.Fatal("Globex is not in the engine")
	}
}

func TestImportName(t *testing.T) {
	existing := []*rmmName{{name: "Contoso"}, {name: "Fabrikam", claimed: true}, {name: "fabrikam (2)"}, {name: "Northwind", claimed: true}}
	for _, c := range []struct {
		name, want string
		join       int
	}{
		{"Contoso", "Contoso", 0},
		{"contoso", "contoso (2)", -1},
		{"Globex", "Globex", -1},
		// What a first run named "fabrikam (2)", found again.
		{"fabrikam", "fabrikam (2)", 2},
		// Claimed by another imported record: the next free name.
		{"Northwind", "Northwind (2)", -1},
		{strings.Repeat("é", 210), strings.Repeat("é", 200), -1},
	} {
		j, got := importName(c.name, existing)
		if got != c.want || (c.join < 0) != (j == nil) || (j != nil && j != existing[c.join]) {
			t.Errorf("%q: %q, %v", c.name, got, j)
		}
	}
	long := strings.Repeat("x", 200)
	if _, got := importName(long, []*rmmName{{name: long, claimed: true}, {name: strings.Repeat("x", 196) + " (2)", claimed: true}}); got != strings.Repeat("x", 196)+" (3)" {
		t.Errorf("long: %q", got)
	}
	if cleanName(" \t\n", "Imported site") != "Imported site" || cleanName("a\x00b\x7f", "") != "a b" {
		t.Error("cleanName")
	}
}
