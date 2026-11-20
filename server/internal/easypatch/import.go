package easypatch

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/tenancy"
)

// Importing a standalone EasyPatch (ADR-0045).
// deploy/scripts/import-easypatch.sh restores its database as the patching
// engine's, then runs `easyrmm-server import-easypatch`, with the server
// stopped, which calls Import: the engine's organizations and sites become
// EasyRMM's. The reconciler then keeps them in step as it does any other,
// and the imported agents link to EasyRMM devices as EasyRMM agents appear
// on them (links.go).

// ImportedRecord is an engine organization or site and the EasyRMM one it
// became.
type ImportedRecord struct {
	Kind       string    `json:"kind"` // organization or site
	EngineID   uuid.UUID `json:"engineId"`
	EngineName string    `json:"engineName"`
	// Organization is a site's EasyRMM organization.
	Organization string    `json:"organization,omitempty"`
	ID           uuid.UUID `json:"id"`
	Name         string    `json:"name"`
	// Joined: EasyRMM had one with exactly this name, which the imported
	// one joined. Otherwise EasyRMM created it.
	Joined bool `json:"joined"`
}

// ImportReport is what Import did.
type ImportReport struct {
	Records []ImportedRecord `json:"records"`
	// Archived organizations and sites stay in the engine, not in EasyRMM.
	ArchivedOrganizations int      `json:"archivedOrganizations"`
	ArchivedSites         int      `json:"archivedSites"`
	Warnings              []string `json:"warnings"`
}

// Count is how many records of kind were joined and created.
func (r *ImportReport) Count(kind string) (joined, created int) {
	for _, x := range r.Records {
		switch {
		case x.Kind != kind:
		case x.Joined:
			joined++
		default:
			created++
		}
	}
	return joined, created
}

// errImportNeedsEngine refuses an import without the engine in the
// deployment.
var errImportNeedsEngine = errors.New("importing EasyPatch needs the patching engine in this deployment")

// rmmName is an EasyRMM organization or site, as the import's name rules
// see it.
type rmmName struct {
	id      uuid.UUID
	name    string
	tz      string
	claimed bool
}

// importName places an engine record named name among EasyRMM's: it joins
// the EasyRMM record with exactly that name, or the first of "name (2)",
// "name (3)" and so on, if no other imported record claimed it; otherwise it
// gets the first of those names that no EasyRMM record has in any case.
// EasyRMM's names are unique ignoring case and EasyPatch's only exactly, so
// two engine records whose names differ only in case stay two records.
// Running the import again finds the same records.
func importName(name string, existing []*rmmName) (*rmmName, string) {
	for n := 1; ; n++ {
		suffix := ""
		if n > 1 {
			suffix = " (" + strconv.Itoa(n) + ")"
		}
		want := fitName(name, suffix)
		if i := slices.IndexFunc(existing, func(x *rmmName) bool { return x.name == want }); i >= 0 && !existing[i].claimed {
			return existing[i], want
		}
		if !slices.ContainsFunc(existing, func(x *rmmName) bool { return strings.EqualFold(x.name, want) }) {
			return nil, want
		}
	}
}

// cleanName is an engine name as EasyRMM accepts one: no control
// characters, trimmed, never empty.
func cleanName(name, fallback string) string {
	name = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, name))
	if name == "" {
		return fallback
	}
	return name
}

// Import makes the engine's active organizations and sites EasyRMM's and
// links them. It first forgets every link to the engine's records, which
// an imported database replaced; devices' opt-outs stay. It is safe to run
// again: it finds what it created by name.
func (s *Service) Import(ctx context.Context, t *tenancy.Service) (ImportReport, error) {
	var rep ImportReport
	if s.engine == nil {
		return rep, errImportNeedsEngine
	}
	c := s.engine.client
	orgs, err := c.AllOrganizations(ctx)
	if err != nil {
		return rep, fmt.Errorf("reading the patching engine's organizations: %s", message(epError(err)))
	}
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		for _, q := range []string{`DELETE FROM easypatch_devices`, `DELETE FROM easypatch_installs`, `DELETE FROM easypatch_sites`,
			`DELETE FROM easypatch_organizations`, `DELETE FROM easypatch_removals`, `DELETE FROM easypatch_forgotten`} {
			if _, err := tx.Exec(ctx, q); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return rep, err
	}
	existing, err := s.rmmNames(ctx, `SELECT id, name, timezone FROM organizations ORDER BY created_at, id`)
	if err != nil {
		return rep, err
	}
	// The same order every time, so that a second run finds the same
	// records.
	slices.SortFunc(orgs, func(a, b Organization) int {
		return cmp.Or(strings.Compare(a.Name, b.Name), strings.Compare(a.ID.String(), b.ID.String()))
	})
	caller := access.System("easypatch-import")
	for _, o := range orgs {
		if !o.IsActive {
			rep.ArchivedOrganizations++
			continue
		}
		name := cleanName(o.Name, "Imported organization")
		tz := o.TimeZone
		if !tenancy.ValidTimezone(tz) {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("Organization %q: its time zone %q is not one EasyRMM knows, so it uses UTC.", o.Name, tz))
			tz = "UTC"
		}
		join, want := importName(name, existing)
		rec := ImportedRecord{Kind: "organization", EngineID: o.ID, EngineName: o.Name, Name: want, Joined: join != nil}
		if join == nil {
			created, err := t.CreateOrganization(ctx, caller, tenancy.OrganizationInput{Name: want, Timezone: tz})
			if err != nil {
				return rep, fmt.Errorf("creating organization %q: %w", want, err)
			}
			join = &rmmName{id: created.ID, name: created.Name, tz: created.Timezone}
			existing = append(existing, join)
		} else if join.tz != tz {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("Organization %q joined EasyRMM's %q, whose time zone (%s) the patching engine now uses instead of %s.",
				o.Name, join.name, join.tz, tz))
		}
		join.claimed, rec.ID = true, join.id
		if err := s.importLink(ctx, rec, uuid.Nil); err != nil {
			return rep, err
		}
		rep.Records = append(rep.Records, rec)
		if err := s.importSites(ctx, t, caller, o, rec, &rep); err != nil {
			return rep, err
		}
	}
	orgsJoined, orgsCreated := rep.Count("organization")
	sitesJoined, sitesCreated := rep.Count("site")
	err = s.audit.Record(ctx, audit.Event{Actor: audit.SystemActor("easypatch-import"), Action: "easypatch.import", Outcome: audit.Success,
		TargetType: "easypatch", TargetID: "engine", Details: map[string]any{
			"organizationsJoined": orgsJoined, "organizationsCreated": orgsCreated, "sitesJoined": sitesJoined, "sitesCreated": sitesCreated,
			"archivedOrganizations": rep.ArchivedOrganizations, "archivedSites": rep.ArchivedSites,
		}})
	return rep, err
}

// importSites does for an imported organization's sites what Import does
// for organizations.
func (s *Service) importSites(ctx context.Context, t *tenancy.Service, caller access.Caller, o Organization, org ImportedRecord, rep *ImportReport) error {
	sites, err := s.engine.client.AllSites(ctx, o.ID)
	if err != nil {
		return fmt.Errorf("reading the sites of %q in the patching engine: %s", o.Name, message(epError(err)))
	}
	existing, err := s.rmmNames(ctx, `SELECT id, name, timezone FROM sites WHERE organization_id = $1 ORDER BY created_at, id`, org.ID)
	if err != nil {
		return err
	}
	slices.SortFunc(sites, func(a, b SiteDetail) int {
		return cmp.Or(strings.Compare(a.Name, b.Name), strings.Compare(a.ID.String(), b.ID.String()))
	})
	for _, x := range sites {
		if !x.IsActive {
			rep.ArchivedSites++
			continue
		}
		tz := x.TimeZone
		if !tenancy.ValidTimezone(tz) {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("Site %q of %q: its time zone %q is not one EasyRMM knows, so it uses UTC.", x.Name, o.Name, tz))
			tz = "UTC"
		}
		join, want := importName(cleanName(x.Name, "Imported site"), existing)
		rec := ImportedRecord{Kind: "site", EngineID: x.ID, EngineName: x.Name, Organization: org.Name, Name: want, Joined: join != nil}
		if join == nil {
			in := tenancy.SiteInput{Name: want, Timezone: tz}
			if x.Address != nil && len([]rune(*x.Address)) <= tenancy.MaxAddressLength {
				in.Address = *x.Address
			}
			created, err := t.CreateSite(ctx, caller, org.ID, in)
			if err != nil {
				return fmt.Errorf("creating site %q of %q: %w", want, org.Name, err)
			}
			join = &rmmName{id: created.ID, name: created.Name, tz: created.Timezone}
			existing = append(existing, join)
		} else if join.tz != tz {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("Site %q of %q joined EasyRMM's %q, whose time zone (%s) the patching engine now uses instead of %s.",
				x.Name, o.Name, join.name, join.tz, tz))
		}
		join.claimed, rec.ID = true, join.id
		if err := s.importLink(ctx, rec, org.ID); err != nil {
			return err
		}
		rep.Records = append(rep.Records, rec)
	}
	return nil
}

// rmmNames reads EasyRMM organizations or sites for importName.
func (s *Service) rmmNames(ctx context.Context, q string, args ...any) ([]*rmmName, error) {
	var out []*rmmName
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		for rows.Next() {
			var x rmmName
			if err := rows.Scan(&x.id, &x.name, &x.tz); err != nil {
				return err
			}
			out = append(out, &x)
		}
		return rows.Err()
	})
	return out, err
}

// importLink links an imported record. Organizations install the agent on
// their devices automatically, as every organization EasyRMM links itself
// does (ADR-0040); agents already there link instead.
func (s *Service) importLink(ctx context.Context, r ImportedRecord, org uuid.UUID) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var err error
		if r.Kind == "organization" {
			_, err = tx.Exec(ctx, `INSERT INTO easypatch_organizations (organization_id, easypatch_id, easypatch_name, auto_install)
				VALUES ($1, $2, $3, true)`, r.ID, r.EngineID, cut(r.EngineName, 200))
		} else {
			_, err = tx.Exec(ctx, `INSERT INTO easypatch_sites (site_id, easypatch_id, easypatch_name) VALUES ($1, $2, $3)`,
				r.ID, r.EngineID, cut(r.EngineName, 200))
		}
		if err != nil {
			return err
		}
		ev := audit.Event{Actor: audit.SystemActor("easypatch-import"), Action: "easypatch." + r.Kind + "_import", Outcome: audit.Success,
			TargetType: r.Kind, TargetID: r.ID.String(),
			Details: map[string]any{"name": r.Name, "easyPatchId": r.EngineID.String(), "easyPatchName": r.EngineName, "joined": r.Joined}}
		if r.Kind == "organization" {
			ev.OrganizationID = r.ID
		} else {
			ev.OrganizationID, ev.SiteID = org, r.ID
		}
		return s.audit.Write(ctx, tx, ev)
	})
}
