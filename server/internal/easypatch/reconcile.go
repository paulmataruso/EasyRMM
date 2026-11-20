package easypatch

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// One set of organizations (one-product plan B5, ADR-0040). With the
// patching engine in the deployment, EasyRMM's organizations, sites and
// devices are the only ones: the reconciler makes the engine's follow them,
// one pass at a time, and carries on after a restart or an outage where it
// stopped. Every step is safe to repeat. What the engine did but EasyRMM
// did not get to record, such as an organization created just before a
// restart, is found again by its name rather than made twice.

const (
	// syncEvery is how often organizations and sites are compared in full
	// when no change asked for it sooner (Kick).
	syncEvery = 5 * time.Minute
	// uninstallGrace is how long an agent has to remove itself before its
	// endpoint is revoked instead, which stops it from patching.
	uninstallGrace = 7 * 24 * time.Hour
	// recheckRemoval is how often an uninstall in progress is looked at.
	recheckRemoval = 5 * time.Minute
	// maxPlacements and maxRemovals bound the engine calls of one pass.
	maxPlacements = 200
	maxRemovals   = 100
	// maxName is EasyPatch's longest organization or site name, in UTF-16
	// code units.
	maxName = 200
)

// Why a device's EasyPatch agent is removed.
const (
	RemovalDeleted  = "deleted"
	RemovalOptedOut = "opted_out"
	RemovalMoved    = "moved"
)

// Removal states.
const (
	removalPending      = "pending"
	removalUninstalling = "uninstalling"
)

// SyncStatus is how keeping the engine in step goes, for Settings.
type SyncStatus struct {
	// At is when the last pass ended.
	At *time.Time `json:"at,omitempty"`
	// Problems are what the last pass could not do; the next one tries
	// again.
	Problems []string `json:"problems"`
	// Archiving counts deleted organizations and sites the engine still has
	// active; Removing, the EasyPatch agents being removed.
	Archiving int `json:"archiving"`
	Removing  int `json:"removing"`
}

// ReconcileResult counts what one pass changed in the patching engine.
type ReconcileResult struct {
	Created, Adopted, Updated, Restored, Archived int
	Moved, Uninstalls, Revoked, Removed           int
	// Problems are what could not be done this pass; the next one tries
	// again.
	Problems []string
}

func (r *ReconcileResult) problem(format string, args ...any) {
	r.Problems = append(r.Problems, cut(fmt.Sprintf(format, args...), 1000))
}

// syncState is the reconciler's memory between passes. Losing it (a
// restart) costs one full pass, nothing else.
type syncState struct {
	mu sync.Mutex
	// full is when organizations and sites were last in step.
	full     time.Time
	at       *time.Time
	problems []string
}

// Kick has the next pass compare organizations and sites in full, and
// starts it if Run is waiting. Tenancy calls it on every change.
func (s *Service) Kick() {
	s.sync.mu.Lock()
	s.sync.full = time.Time{}
	s.sync.mu.Unlock()
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// Reconcile makes one pass: deleted organizations and sites archived,
// organizations and sites created, renamed and given EasyRMM's time zones,
// endpoints put in their device's site, and EasyPatch agents removed where
// EasyRMM asked. Engine failures are Problems for the next pass; an error
// is EasyRMM's own (its database).
func (s *Service) Reconcile(ctx context.Context) (ReconcileResult, error) {
	var res ReconcileResult
	r, c, err := s.conn(ctx)
	if err != nil {
		return res, err
	}
	if r == nil {
		return res, nil
	}
	now := s.now()
	s.sync.mu.Lock()
	due := now.Sub(s.sync.full) >= syncEvery
	s.sync.mu.Unlock()
	if due {
		before := len(res.Problems)
		if err := s.archiveForgotten(ctx, c, &res); err != nil {
			return res, err
		}
		orgs, err := s.syncOrganizations(ctx, c, &res)
		if err != nil {
			return res, err
		}
		if err := s.syncSites(ctx, c, orgs, &res); err != nil {
			return res, err
		}
		if len(res.Problems) == before {
			s.sync.mu.Lock()
			s.sync.full = now
			s.sync.mu.Unlock()
		}
	}
	if err := s.placeEndpoints(ctx, c, &res); err != nil {
		return res, err
	}
	s.syncMail(ctx, c, &res)
	if err := s.removeAgents(ctx, c, &res); err != nil {
		return res, err
	}
	if res.Created+res.Adopted+res.Moved+res.Removed > 0 {
		s.fleet.clear()
	}
	end := s.now()
	s.sync.mu.Lock()
	s.sync.at, s.sync.problems = &end, slices.Clone(res.Problems)
	s.sync.mu.Unlock()
	for _, p := range res.Problems {
		s.log.Warn("easypatch: keeping the patching engine in step", "problem", p)
	}
	return res, nil
}

// Sync reports how keeping the engine in step goes.
func (s *Service) Sync(ctx context.Context) (SyncStatus, error) {
	s.sync.mu.Lock()
	out := SyncStatus{At: s.sync.at, Problems: append([]string{}, s.sync.problems...)}
	s.sync.mu.Unlock()
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM easypatch_forgotten), (SELECT count(*) FROM easypatch_removals)`).
			Scan(&out.Archiving, &out.Removing)
	})
	return out, err
}

// ---------------------------------------------------------------- names

func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if w := utf16.RuneLen(r); w > 0 {
			n += w
		} else {
			n++
		}
	}
	return n
}

// fitName is name, shortened to leave room for suffix, then suffix: an
// engine name.
func fitName(name, suffix string) string {
	limit := maxName - utf16Len(suffix)
	var b strings.Builder
	n := 0
	for _, r := range strings.TrimSpace(name) {
		w := utf16.RuneLen(r)
		if w < 0 {
			w = 1
		}
		if n+w > limit {
			break
		}
		b.WriteRune(r)
		n += w
	}
	return strings.TrimSpace(b.String()) + suffix
}

// shortID is the start of an id, which names tell apart by.
func shortID(id uuid.UUID) string { return id.String()[:8] }

// named is an engine organization or site, as the name rules see it.
type named struct {
	id     uuid.UUID
	name   string
	active bool
}

// nameSet hands out engine names. EasyRMM's are unique ignoring case;
// EasyPatch's are unique exactly, archived ones included. A name another
// engine record holds, in any case, is taken: the record then gets its
// EasyRMM name with its id's start, and its plain name back once that is
// free.
type nameSet struct{ all []*named }

func (n *nameSet) taken(name string, except uuid.UUID) bool {
	return slices.ContainsFunc(n.all, func(x *named) bool { return x.id != except && strings.EqualFold(x.name, name) })
}

// want is the engine name for EasyRMM's name of record id, held now by the
// engine record except (uuid.Nil: a new one).
func (n *nameSet) want(name string, id, except uuid.UUID) (string, error) {
	base := fitName(name, "")
	if !n.taken(base, except) {
		return base, nil
	}
	alt := fitName(name, " ("+shortID(id)+")")
	if !n.taken(alt, except) {
		return alt, nil
	}
	return "", fmt.Errorf("both %q and %q are taken in the patching engine", base, alt)
}

// adoptable is an active engine record nothing is linked to, named as
// EasyRMM would have named it: one EasyRMM created before a restart lost
// the link, or one there was before the engine was EasyRMM's.
func (n *nameSet) adoptable(name string, id uuid.UUID, linked map[uuid.UUID]bool) *named {
	base, alt := fitName(name, ""), fitName(name, " ("+shortID(id)+")")
	for _, x := range n.all {
		if x.active && !linked[x.id] && (x.name == base || x.name == alt) {
			return x
		}
	}
	return nil
}

// ---------------------------------------------------------------- deleted organizations and sites

type forgottenRow struct {
	kind string
	id   uuid.UUID
	name string
	at   time.Time
}

// archiveForgotten archives in the engine the organizations and sites
// EasyRMM deleted, renamed with a suffix that frees their names.
func (s *Service) archiveForgotten(ctx context.Context, c *Client, res *ReconcileResult) error {
	var list []forgottenRow
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		// Sites first, then their organizations.
		rows, err := tx.Query(ctx, `SELECT kind, easypatch_id, name, forgotten_at FROM easypatch_forgotten
			ORDER BY kind DESC, forgotten_at LIMIT 200`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var f forgottenRow
			if err := rows.Scan(&f.kind, &f.id, &f.name, &f.at); err != nil {
				return err
			}
			list = append(list, f)
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	for _, f := range list {
		problem := s.archiveOne(ctx, c, f)
		err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
			if problem != "" {
				_, err := tx.Exec(ctx, `UPDATE easypatch_forgotten SET last_error = $3 WHERE kind = $1 AND easypatch_id = $2`,
					f.kind, f.id, cut(problem, 1000))
				return err
			}
			if _, err := tx.Exec(ctx, `DELETE FROM easypatch_forgotten WHERE kind = $1 AND easypatch_id = $2`, f.kind, f.id); err != nil {
				return err
			}
			return s.audit.Write(ctx, tx, audit.Event{Actor: audit.SystemActor("easypatch"), Action: "easypatch." + f.kind + "_archive",
				TargetType: "easypatch_" + f.kind, TargetID: f.id.String(), Outcome: audit.Success,
				Details: map[string]any{"name": f.name, "reason": "deleted in EasyRMM"}})
		})
		if err != nil {
			return err
		}
		if problem != "" {
			res.problem("%s", problem)
			continue
		}
		res.Archived++
	}
	return nil
}

// archiveOne renames and archives one engine record; "" when done.
func (s *Service) archiveOne(ctx context.Context, c *Client, f forgottenRow) string {
	marker := fmt.Sprintf(" (deleted %s %s)", f.at.UTC().Format("2006-01-02"), shortID(f.id))
	fail := func(what string, err error) string {
		s.noteError(err)
		return fmt.Sprintf("Archiving %s %q, deleted in EasyRMM: %s: %s", strings.ReplaceAll(f.kind, "_", " "), f.name, what, message(epError(err)))
	}
	switch f.kind {
	case "organization":
		o, err := c.GetOrganization(ctx, f.id)
		if IsStatus(err, http.StatusNotFound) {
			return ""
		}
		if err != nil {
			return fail("reading it", err)
		}
		if !strings.HasSuffix(o.Name, marker) {
			o.Name = fitName(o.Name, marker)
			if _, err := c.UpdateOrganization(ctx, o); err != nil {
				return fail("renaming it", err)
			}
		}
		if o.IsActive {
			if err := c.ArchiveOrganization(ctx, f.id); err != nil && !IsStatus(err, http.StatusNotFound) {
				return fail("archiving it", err)
			}
		}
	default:
		x, err := c.GetSite(ctx, f.id)
		if IsStatus(err, http.StatusNotFound) {
			return ""
		}
		if err != nil {
			return fail("reading it", err)
		}
		if !strings.HasSuffix(x.Name, marker) {
			x.Name = fitName(x.Name, marker)
			if _, err := c.UpdateSite(ctx, x); err != nil {
				return fail("renaming it", err)
			}
		}
		if x.IsActive {
			if err := c.ArchiveSite(ctx, f.id); err != nil && !IsStatus(err, http.StatusNotFound) {
				return fail("archiving it", err)
			}
		}
	}
	return ""
}

// ---------------------------------------------------------------- organizations

type rmmRecord struct {
	id, org  uuid.UUID
	name, tz string
	link     *uuid.UUID
	linkName string
}

// syncOrganizations gives every EasyRMM organization an engine
// organization, named and set to the time zone as in EasyRMM. It returns
// the links that hold, EasyRMM's id to the engine's; none when the engine
// could not be read.
func (s *Service) syncOrganizations(ctx context.Context, c *Client, res *ReconcileResult) (map[uuid.UUID]uuid.UUID, error) {
	var orgs []rmmRecord
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT o.id, o.name, o.timezone, l.easypatch_id, coalesce(l.easypatch_name, '')
			FROM organizations o LEFT JOIN easypatch_organizations l ON l.organization_id = o.id ORDER BY o.created_at, o.id`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var o rmmRecord
			if err := rows.Scan(&o.id, &o.name, &o.tz, &o.link, &o.linkName); err != nil {
				return err
			}
			orgs = append(orgs, o)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	list, err := c.AllOrganizations(ctx)
	if err != nil {
		s.noteError(err)
		res.problem("Reading the patching engine's organizations: %s", message(epError(err)))
		return nil, nil
	}
	n := nameSet{}
	engine := map[uuid.UUID]*named{}
	zones := map[uuid.UUID]string{}
	for _, o := range list {
		x := &named{id: o.ID, name: o.Name, active: o.IsActive}
		n.all = append(n.all, x)
		engine[o.ID], zones[o.ID] = x, o.TimeZone
	}
	linked := map[uuid.UUID]bool{}
	for _, o := range orgs {
		if o.link != nil && engine[*o.link] != nil {
			linked[*o.link] = true
		}
	}
	out := map[uuid.UUID]uuid.UUID{}
	for _, o := range orgs {
		var ep *named
		if o.link != nil {
			ep = engine[*o.link]
		}
		if o.link != nil && ep == nil {
			// The engine no longer has it (deleted there): start again.
			if err := s.dropLink(ctx, "organization", o.id, *o.link); err != nil {
				return nil, err
			}
		}
		created := false
		if ep == nil {
			ep = n.adoptable(o.name, o.id, linked)
			if ep == nil {
				name, err := n.want(o.name, o.id, uuid.Nil)
				if err != nil {
					res.problem("Organization %q: %v", o.name, err)
					continue
				}
				d, err := c.CreateOrganization(ctx, name, o.tz)
				if err != nil {
					s.noteError(err)
					res.problem("Creating organization %q in the patching engine: %s", o.name, message(epError(err)))
					continue
				}
				ep = &named{id: d.ID, name: d.Name, active: true}
				n.all = append(n.all, ep)
				zones[d.ID], created = d.TimeZone, true
			}
			linked[ep.id] = true
			ok, err := s.linkRecord(ctx, "organization", o, ep, created)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue // deleted meanwhile: archived next pass
			}
			if created {
				res.Created++
			} else {
				res.Adopted++
			}
			o.linkName = ep.name
		}
		if !ep.active {
			if err := c.RestoreOrganization(ctx, ep.id); err != nil {
				s.noteError(err)
				res.problem("Restoring organization %q in the patching engine: %s", o.name, message(epError(err)))
				continue
			}
			ep.active = true
			res.Restored++
		}
		name, err := n.want(o.name, o.id, ep.id)
		if err != nil {
			res.problem("Organization %q: %v", o.name, err)
		} else if ep.name != name || zones[ep.id] != o.tz {
			d, err := c.GetOrganization(ctx, ep.id)
			if err == nil {
				d.Name, d.TimeZone = name, o.tz
				_, err = c.UpdateOrganization(ctx, d)
			}
			if err != nil {
				s.noteError(err)
				res.problem("Updating organization %q in the patching engine: %s", o.name, message(epError(err)))
			} else {
				ep.name, zones[ep.id] = name, o.tz
				res.Updated++
			}
		}
		if o.linkName != ep.name {
			if err := s.renameLink(ctx, "organization", o.id, ep.name); err != nil {
				return nil, err
			}
		}
		out[o.id] = ep.id
	}
	return out, nil
}

// linkRecord links an EasyRMM organization or site to the engine's, false
// when EasyRMM deleted it meanwhile: the engine's is then forgotten, to be
// archived.
func (s *Service) linkRecord(ctx context.Context, kind string, r rmmRecord, ep *named, created bool) (bool, error) {
	action := "easypatch." + kind + "_adopt"
	if created {
		action = "easypatch." + kind + "_create"
	}
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		ev := audit.Event{Actor: audit.SystemActor("easypatch"), Action: action, Outcome: audit.Success,
			Details: map[string]any{"name": r.name, "easyPatchId": ep.id.String(), "easyPatchName": ep.name}}
		if kind == "organization" {
			// Automatic installs are on for organizations EasyRMM links
			// itself (one-product plan, B5); a link already there keeps its
			// setting.
			if _, err := tx.Exec(ctx, `INSERT INTO easypatch_organizations (organization_id, easypatch_id, easypatch_name, auto_install)
				VALUES ($1, $2, $3, true)
				ON CONFLICT (organization_id) DO UPDATE SET easypatch_id = $2, easypatch_name = $3, linked_at = now(), linked_by = NULL`,
				r.id, ep.id, ep.name); err != nil {
				return err
			}
			if err := recheckOrganization(ctx, tx, r.id); err != nil {
				return err
			}
			ev.OrganizationID, ev.TargetType, ev.TargetID = r.id, "organization", r.id.String()
		} else {
			if _, err := tx.Exec(ctx, `INSERT INTO easypatch_sites (site_id, easypatch_id, easypatch_name) VALUES ($1, $2, $3)
				ON CONFLICT (site_id) DO UPDATE SET easypatch_id = $2, easypatch_name = $3, linked_at = now()`,
				r.id, ep.id, ep.name); err != nil {
				return err
			}
			ev.OrganizationID, ev.SiteID, ev.TargetType, ev.TargetID = r.org, r.id, "site", r.id.String()
		}
		return s.audit.Write(ctx, tx, ev)
	})
	if database.IsForeignKeyViolation(err) {
		return false, s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO easypatch_forgotten (kind, easypatch_id, name) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
				kind, ep.id, cut(ep.name, 200))
			return err
		})
	}
	return err == nil, err
}

func (s *Service) renameLink(ctx context.Context, kind string, id uuid.UUID, name string) error {
	q := `UPDATE easypatch_organizations SET easypatch_name = $2 WHERE organization_id = $1`
	if kind == "site" {
		q = `UPDATE easypatch_sites SET easypatch_name = $2 WHERE site_id = $1`
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, q, id, cut(name, 200))
		return err
	})
}

// dropLink forgets a link to an engine record that is gone; an
// organization's site links go with it.
func (s *Service) dropLink(ctx context.Context, kind string, id, easyPatchID uuid.UUID) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if kind == "site" {
			_, err := tx.Exec(ctx, `DELETE FROM easypatch_sites WHERE site_id = $1 AND easypatch_id = $2`, id, easyPatchID)
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM easypatch_sites WHERE site_id IN (SELECT id FROM sites WHERE organization_id = $1)`, id); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM easypatch_organizations WHERE organization_id = $1 AND easypatch_id = $2`, id, easyPatchID)
		return err
	})
}

// ---------------------------------------------------------------- sites

// syncSites does for each linked organization's sites what
// syncOrganizations does for organizations.
func (s *Service) syncSites(ctx context.Context, c *Client, orgs map[uuid.UUID]uuid.UUID, res *ReconcileResult) error {
	if len(orgs) == 0 {
		return nil
	}
	bySite := map[uuid.UUID][]rmmRecord{}
	var order []uuid.UUID
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT s.id, s.organization_id, s.name, s.timezone, l.easypatch_id, coalesce(l.easypatch_name, '')
			FROM sites s LEFT JOIN easypatch_sites l ON l.site_id = s.id ORDER BY s.organization_id, s.created_at, s.id`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var r rmmRecord
			if err := rows.Scan(&r.id, &r.org, &r.name, &r.tz, &r.link, &r.linkName); err != nil {
				return err
			}
			if _, ok := bySite[r.org]; !ok {
				order = append(order, r.org)
			}
			bySite[r.org] = append(bySite[r.org], r)
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	for _, org := range order {
		epOrg, ok := orgs[org]
		if !ok {
			continue
		}
		list, err := c.AllSites(ctx, epOrg)
		if err != nil {
			s.noteError(err)
			res.problem("Reading the sites of an organization in the patching engine: %s", message(epError(err)))
			continue
		}
		if err := s.syncOrgSites(ctx, c, epOrg, bySite[org], list, res); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) syncOrgSites(ctx context.Context, c *Client, epOrg uuid.UUID, sites []rmmRecord, list []SiteDetail, res *ReconcileResult) error {
	n := nameSet{}
	engine := map[uuid.UUID]*named{}
	zones := map[uuid.UUID]string{}
	for _, x := range list {
		e := &named{id: x.ID, name: x.Name, active: x.IsActive}
		n.all = append(n.all, e)
		engine[x.ID], zones[x.ID] = e, x.TimeZone
	}
	linked := map[uuid.UUID]bool{}
	for _, r := range sites {
		if r.link != nil && engine[*r.link] != nil {
			linked[*r.link] = true
		}
	}
	for _, r := range sites {
		var ep *named
		if r.link != nil {
			ep = engine[*r.link]
		}
		if r.link != nil && ep == nil {
			// Gone, or of another engine organization: start again.
			if err := s.dropLink(ctx, "site", r.id, *r.link); err != nil {
				return err
			}
		}
		created := false
		if ep == nil {
			ep = n.adoptable(r.name, r.id, linked)
			if ep == nil {
				name, err := n.want(r.name, r.id, uuid.Nil)
				if err != nil {
					res.problem("Site %q: %v", r.name, err)
					continue
				}
				d, err := c.CreateSite(ctx, epOrg, name, r.tz)
				if err != nil {
					s.noteError(err)
					res.problem("Creating site %q in the patching engine: %s", r.name, message(epError(err)))
					continue
				}
				ep = &named{id: d.ID, name: d.Name, active: true}
				n.all = append(n.all, ep)
				zones[d.ID], created = d.TimeZone, true
			}
			linked[ep.id] = true
			ok, err := s.linkRecord(ctx, "site", r, ep, created)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			if created {
				res.Created++
			} else {
				res.Adopted++
			}
			r.linkName = ep.name
		}
		if !ep.active {
			if err := c.RestoreSite(ctx, ep.id); err != nil {
				s.noteError(err)
				res.problem("Restoring site %q in the patching engine: %s", r.name, message(epError(err)))
				continue
			}
			ep.active = true
			res.Restored++
		}
		name, err := n.want(r.name, r.id, ep.id)
		if err != nil {
			res.problem("Site %q: %v", r.name, err)
		} else if ep.name != name || zones[ep.id] != r.tz {
			d, err := c.GetSite(ctx, ep.id)
			if err == nil {
				d.Name, d.TimeZone = name, r.tz
				_, err = c.UpdateSite(ctx, d)
			}
			if err != nil {
				s.noteError(err)
				res.problem("Updating site %q in the patching engine: %s", r.name, message(epError(err)))
			} else {
				ep.name, zones[ep.id] = name, r.tz
				res.Updated++
			}
		}
		if r.linkName != ep.name {
			if err := s.renameLink(ctx, "site", r.id, ep.name); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------- endpoints

// placeEndpoints puts each linked device's endpoint in the engine site of
// the device's site, as after a device moves between sites.
func (s *Service) placeEndpoints(ctx context.Context, c *Client, res *ReconcileResult) error {
	type placement struct{ device, endpoint, site uuid.UUID }
	var list []placement
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT e.device_id, e.endpoint_id, ls.easypatch_id
			FROM easypatch_devices e JOIN devices d ON d.id = e.device_id
			JOIN easypatch_organizations lo ON lo.organization_id = d.organization_id
			JOIN easypatch_sites ls ON ls.site_id = d.site_id
			WHERE e.state = 'linked' AND e.easypatch_org_id = lo.easypatch_id AND e.easypatch_site_id IS DISTINCT FROM ls.easypatch_id
			ORDER BY e.device_id LIMIT $1`, maxPlacements)
		if err != nil {
			return err
		}
		for rows.Next() {
			var p placement
			if err := rows.Scan(&p.device, &p.endpoint, &p.site); err != nil {
				return err
			}
			list = append(list, p)
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	for _, p := range list {
		err := c.MoveEndpoint(ctx, p.endpoint, &p.site)
		q := `UPDATE easypatch_devices SET easypatch_site_id = $3 WHERE device_id = $1 AND endpoint_id = $2`
		switch {
		case err == nil:
			res.Moved++
		case IsStatus(err, http.StatusNotFound), IsStatus(err, http.StatusBadRequest):
			// Gone, or in another engine organization: the link's check says
			// which.
			q = `UPDATE easypatch_devices SET state = 'pending', reason = '', checked_at = NULL WHERE device_id = $1 AND endpoint_id = $2
				AND $3::uuid IS NOT NULL`
		default:
			s.noteError(err)
			res.problem("Moving an endpoint to its device's site: %s", message(epError(err)))
			return nil
		}
		if err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, q, p.device, p.endpoint, p.site)
			return err
		}); err != nil {
			return err
		}
	}
	return nil
}

type removalRow struct {
	endpoint     uuid.UUID
	device       *uuid.UUID
	reason, host string
	state        string
	job          *uuid.UUID
	sentAt       *time.Time
	attempts     int
	cancel       string
}

// removeAgents has the agents EasyRMM asked to remove uninstall themselves,
// and revokes the endpoints of those that cannot or do not in time.
func (s *Service) removeAgents(ctx context.Context, c *Client, res *ReconcileResult) error {
	now := s.now()
	var list []removalRow
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		// cancel says why a removal not sent yet is no longer wanted: the
		// endpoint is a device's EasyRMM still has, or patching was allowed
		// again.
		rows, err := tx.Query(ctx, `SELECT r.endpoint_id, r.device_id, r.reason, r.hostname, r.state, r.job_id, r.sent_at, r.attempts,
				CASE WHEN r.state <> 'pending' THEN ''
					WHEN r.reason = 'opted_out' AND (r.device_id IS NULL OR NOT EXISTS (SELECT 1 FROM easypatch_opt_outs o WHERE o.device_id = r.device_id))
						THEN 'patching was allowed again'
					WHEN r.reason <> 'opted_out' AND EXISTS (SELECT 1 FROM easypatch_devices e WHERE e.endpoint_id = r.endpoint_id AND e.state = 'linked')
						THEN 'a device in EasyRMM is linked to it'
					WHEN r.reason = 'deleted' AND EXISTS (SELECT 1 FROM device_inventory i
							WHERE lower(i.data->'easyPatch'->>'endpointId') = r.endpoint_id::text)
						THEN 'a device in EasyRMM reports it'
					ELSE '' END
			FROM easypatch_removals r
			WHERE r.state = 'pending' OR r.checked_at IS NULL OR r.checked_at < $1
			ORDER BY r.requested_at LIMIT $2`, now.Add(-recheckRemoval), maxRemovals)
		if err != nil {
			return err
		}
		for rows.Next() {
			var x removalRow
			if err := rows.Scan(&x.endpoint, &x.device, &x.reason, &x.host, &x.state, &x.job, &x.sentAt, &x.attempts, &x.cancel); err != nil {
				return err
			}
			list = append(list, x)
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	for i := range list {
		x := &list[i]
		var step removalStep
		if x.cancel != "" {
			step = removalStep{done: true, note: "no longer wanted: " + x.cancel}
		} else {
			step = s.removalStep(ctx, c, x, now)
		}
		if step.stop {
			res.problem("%s", step.problem)
			return nil // the engine is not answering; next pass
		}
		if err := s.saveRemoval(ctx, x, step); err != nil {
			return err
		}
		switch {
		case step.problem != "":
			res.problem("%s", step.problem)
		case step.sent:
			res.Uninstalls++
		}
		if step.revoked {
			res.Revoked++
		}
		if step.done && x.cancel == "" {
			res.Removed++
		}
	}
	return nil
}

// removalStep is what one look at a removal decided.
type removalStep struct {
	// sent: the uninstall job is queued (job, if known); done: nothing is
	// left to do; again: send the uninstall again.
	sent, done, again, revoked bool
	job                        *uuid.UUID
	note, problem              string
	// stop: the engine is not answering; the pass ends.
	stop bool
}

func (s *Service) removalStep(ctx context.Context, c *Client, x *removalRow, now time.Time) removalStep {
	who := x.host
	if who == "" {
		who = "endpoint " + x.endpoint.String()
	}
	engineDown := func(err error) removalStep {
		s.noteError(err)
		return removalStep{stop: true, problem: fmt.Sprintf("Removing the EasyPatch agent of %s: %s", who, message(epError(err)))}
	}
	revoke := func(why string) removalStep {
		err := c.RevokeEndpoint(ctx, x.endpoint, cut("EasyRMM: "+why, 500))
		if err != nil && !IsStatus(err, http.StatusNotFound) {
			return engineDown(err)
		}
		return removalStep{done: true, revoked: err == nil, note: why}
	}
	if x.state == removalPending {
		j, err := c.UninstallAgent(ctx, x.endpoint)
		switch code := errorCode(err); {
		case err == nil:
			return removalStep{sent: true, job: &j.ID}
		case code == "duplicate_job":
			return removalStep{sent: true}
		case IsStatus(err, http.StatusNotFound), code == "endpoint_not_active":
			return removalStep{done: true, note: "the endpoint is not active"}
		case code == "agent_upgrade_required":
			// Agents before 1.6.0 cannot remove themselves: revoked, they
			// stop patching.
			return revoke(fmt.Sprintf("its agent is too old to uninstall itself (%s)", reasonText(x.reason)))
		case IsStatus(err, http.StatusConflict), IsStatus(err, http.StatusBadRequest), IsStatus(err, http.StatusForbidden):
			s.noteError(err)
			return removalStep{problem: fmt.Sprintf("Removing the EasyPatch agent of %s: %s", who, message(epError(err)))}
		default:
			return engineDown(err)
		}
	}
	ep, err := c.Endpoint(ctx, x.endpoint)
	switch {
	case IsStatus(err, http.StatusNotFound):
		return removalStep{done: true, note: "the endpoint is gone"}
	case err != nil:
		return engineDown(err)
	case ep.Summary.Status != "Active":
		return removalStep{done: true, note: "the agent removed itself"}
	case x.sentAt != nil && now.Sub(*x.sentAt) >= uninstallGrace:
		return revoke(fmt.Sprintf("its agent did not uninstall itself within %d days (%s)", int(uninstallGrace.Hours()/24), reasonText(x.reason)))
	case x.job == nil:
		return removalStep{}
	}
	jd, err := c.Job(ctx, *x.job)
	switch {
	case IsStatus(err, http.StatusNotFound):
		return removalStep{again: true, note: "the uninstall job is gone"}
	case err != nil:
		return engineDown(err)
	}
	switch st := jd.Summary.Status; st {
	case "Queued", "Delivered", "Acknowledged", "Running", "WaitingForReboot", "Completed":
		// Completed: the agent unenrolls as it goes; the endpoint follows.
		return removalStep{}
	default:
		why := strings.ToLower(st)
		if jd.Summary.ErrorMessage != "" {
			why += ": " + jd.Summary.ErrorMessage
		}
		return removalStep{again: true, note: "the uninstall job " + why}
	}
}

func reasonText(reason string) string {
	switch reason {
	case RemovalDeleted:
		return "the device was deleted in EasyRMM"
	case RemovalOptedOut:
		return "patching was stopped for the device in EasyRMM"
	case RemovalMoved:
		return "the device moved to another organization in EasyRMM"
	}
	return reason
}

// saveRemoval records a step. A moved device's install record is cleared
// when its old agent is gone, so automatic installs put the agent back in
// its new organization.
func (s *Service) saveRemoval(ctx context.Context, x *removalRow, st removalStep) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var err error
		switch {
		case st.done:
			_, err = tx.Exec(ctx, `DELETE FROM easypatch_removals WHERE endpoint_id = $1`, x.endpoint)
			if err == nil && x.device != nil && x.reason == RemovalMoved && x.cancel == "" {
				_, err = tx.Exec(ctx, `DELETE FROM easypatch_installs WHERE device_id = $1 AND state IN ('succeeded', 'failed')`, *x.device)
			}
		case st.sent:
			_, err = tx.Exec(ctx, `UPDATE easypatch_removals SET state = 'uninstalling', job_id = $2, sent_at = now(), checked_at = now(),
				attempts = attempts + 1, last_error = '' WHERE endpoint_id = $1`, x.endpoint, st.job)
		case st.again:
			_, err = tx.Exec(ctx, `UPDATE easypatch_removals SET state = 'pending', job_id = NULL, checked_at = now(), last_error = $2
				WHERE endpoint_id = $1`, x.endpoint, cut(st.note, 1000))
		case st.problem != "":
			_, err = tx.Exec(ctx, `UPDATE easypatch_removals SET checked_at = now(), attempts = attempts + 1, last_error = $2
				WHERE endpoint_id = $1`, x.endpoint, cut(st.problem, 1000))
		default:
			_, err = tx.Exec(ctx, `UPDATE easypatch_removals SET checked_at = now() WHERE endpoint_id = $1`, x.endpoint)
		}
		if err != nil || (!st.sent && !st.revoked && (!st.done || x.cancel != "")) {
			return err
		}
		ev := audit.Event{Actor: audit.SystemActor("easypatch"), Action: "easypatch.agent_remove", TargetType: "easypatch_endpoint",
			TargetID: x.endpoint.String(), Outcome: audit.Success,
			Details: map[string]any{"device": x.host, "reason": x.reason}}
		switch {
		case st.revoked:
			ev.Action, ev.Details["note"] = "easypatch.endpoint_revoke", st.note
		case st.sent:
			ev.Action = "easypatch.agent_uninstall"
		default:
			ev.Details["note"] = st.note
		}
		if x.device != nil {
			ev.DeviceID = *x.device
		}
		return s.audit.Write(ctx, tx, ev)
	})
}
