package easypatch

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Patch all (ADR-0030, amended 2026-11-22): an install or a restart of every
// device of an organization, or of one of its sites, that the caller may
// patch. The devices are read when the request runs, never taken from the
// console, so an organization of any size is sent whole, in batches the
// engine takes, and devices enrolled since the dialog opened are included.

// Why a device of a scope is left out.
const (
	SkipNotPermitted = "not_permitted"
	SkipStopped      = "stopped"
	SkipNoAgent      = "no_agent"
	SkipNotLinked    = "not_linked"
	SkipPlatform     = "platform"
)

// skipOrder is the order reasons are listed in.
var skipOrder = []string{SkipNotPermitted, SkipStopped, SkipNoAgent, SkipNotLinked, SkipPlatform}

// devicePlatforms are the platforms a device can have.
var devicePlatforms = []string{"windows", "linux", "macos", "other"}

// Targets chooses the devices of an action: DeviceIDs, or with All every
// device of OrganizationID (only SiteID's, when it is set) that the caller
// may patch, on Platforms (every platform when empty).
type Targets struct {
	DeviceIDs      []uuid.UUID `json:"deviceIds"`
	All            bool        `json:"all"`
	OrganizationID uuid.UUID   `json:"organizationId"`
	SiteID         uuid.UUID   `json:"siteId"`
	Platforms      []string    `json:"platforms"`
}

// ScopeQuery is the organization, or site, of a Patch all.
type ScopeQuery struct {
	OrganizationID, SiteID uuid.UUID
}

// PlatformCount is how many devices of a scope run a platform.
type PlatformCount struct {
	Platform string `json:"platform"`
	Count    int    `json:"count"`
}

// SkipCount is how many devices of a scope are left out, and why.
type SkipCount struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

// ScopeView is what a Patch all would reach.
type ScopeView struct {
	OrganizationID   uuid.UUID  `json:"organizationId"`
	OrganizationName string     `json:"organizationName"`
	SiteID           *uuid.UUID `json:"siteId"`
	SiteName         string     `json:"siteName"`
	// Devices are linked to an EasyPatch agent, not stopped, and the caller
	// may patch them; ByPlatform counts them by platform.
	Devices    int             `json:"devices"`
	ByPlatform []PlatformCount `json:"byPlatform"`
	// Skipped counts the devices the caller sees that are left out.
	Skipped []SkipCount `json:"skipped"`
	// CanManage says the caller may install and restart in the scope.
	CanManage bool `json:"canManage"`
}

// scope is a resolved Patch all: its devices, and what was left out.
type scope struct {
	view    ScopeView
	devices []deviceRow
	// epOrg is the organization's in the engine.
	epOrg uuid.UUID
}

func (sc *scope) skip(reason string) {
	for i := range sc.view.Skipped {
		if sc.view.Skipped[i].Reason == reason {
			sc.view.Skipped[i].Count++
			return
		}
	}
	sc.view.Skipped = append(sc.view.Skipped, SkipCount{Reason: reason, Count: 1})
}

// Scope says what a Patch all of an organization, or a site, would reach.
func (s *Service) Scope(ctx context.Context, c access.Caller, q ScopeQuery) (ScopeView, error) {
	if _, _, err := s.operable(ctx); err != nil {
		return ScopeView{}, err
	}
	sc, err := s.resolveTargets(ctx, c, q, nil)
	if err != nil {
		return ScopeView{}, err
	}
	return sc.view, nil
}

// resolveTargets reads the devices of an organization, or site, that an
// action would reach, with platforms narrowing them (every platform when
// empty). It never fails for the caller's permissions on devices: those
// they may not patch are counted as left out.
func (s *Service) resolveTargets(ctx context.Context, c access.Caller, q ScopeQuery, platforms []string) (*scope, error) {
	// An empty list is refused, not read as every platform: a request that
	// lost its platforms must not reach every device.
	if platforms != nil && len(platforms) == 0 {
		return nil, apperr.Invalid("platforms", "Choose at least one platform, or leave platforms out for every platform.")
	}
	for _, p := range platforms {
		if !slices.Contains(devicePlatforms, p) {
			return nil, apperr.Invalid("platforms", "Choose Windows, Linux, macOS or other devices.")
		}
	}
	if q.OrganizationID == uuid.Nil {
		return nil, apperr.Invalid("organizationId", "Choose an organization.")
	}
	sc := &scope{view: ScopeView{OrganizationID: q.OrganizationID, ByPlatform: []PlatformCount{}, Skipped: []SkipCount{}}}
	var epOrg *uuid.UUID
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT o.name, l.easypatch_id FROM organizations o
			LEFT JOIN easypatch_organizations l ON l.organization_id = o.id WHERE o.id = $1`, q.OrganizationID).
			Scan(&sc.view.OrganizationName, &epOrg)
		if err != nil {
			return err
		}
		if q.SiteID != uuid.Nil {
			var org uuid.UUID
			if err := tx.QueryRow(ctx, `SELECT organization_id, name FROM sites WHERE id = $1`, q.SiteID).Scan(&org, &sc.view.SiteName); err != nil {
				return err
			}
			if org != q.OrganizationID {
				return apperr.Invalid("siteId", "Choose a site of the organization.")
			}
		}
		return nil
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, apperr.NotFound()
	case err != nil:
		return nil, err
	}
	where := rbac.Org(q.OrganizationID)
	if q.SiteID != uuid.Nil {
		id := q.SiteID
		sc.view.SiteID, where = &id, rbac.Site(q.OrganizationID, q.SiteID)
	}
	visible := c.CanInOrg(rbac.PermPatchView, q.OrganizationID)
	if q.SiteID != uuid.Nil {
		visible = c.Can(rbac.PermPatchView, where)
	}
	switch {
	case !visible:
		return nil, apperr.NotFound()
	case epOrg == nil:
		return nil, errOrgNotLinked
	}
	sc.epOrg = *epOrg
	sc.view.CanManage = c.Can(rbac.PermPatchManage, where)
	if q.SiteID == uuid.Nil {
		sc.view.CanManage = c.CanInOrg(rbac.PermPatchManage, q.OrganizationID)
	}
	byPlatform := map[string]int{}
	err = s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, deviceSelect+` WHERE d.organization_id = $1 AND ($2::uuid IS NULL OR d.site_id = $2) ORDER BY d.name, d.id`,
			q.OrganizationID, nullID(q.SiteID))
		if err != nil {
			return err
		}
		for rows.Next() {
			d, err := scanDevice(rows)
			if err != nil {
				return err
			}
			r := d.resource()
			switch {
			case !c.Can(rbac.PermDeviceView, r) || !c.Can(rbac.PermPatchView, r):
				// Devices the caller cannot see are not counted at all.
			case !c.Can(rbac.PermPatchManage, r):
				sc.skip(SkipNotPermitted)
			case d.stopped != nil || d.removal != nil:
				sc.skip(SkipStopped)
			case d.state == LinkNone || d.state == "":
				sc.skip(SkipNoAgent)
			case d.state != LinkLinked || d.endpointID == nil || d.easyPatchOrg == nil:
				sc.skip(SkipNotLinked)
			case len(platforms) > 0 && !slices.Contains(platforms, d.platform):
				sc.skip(SkipPlatform)
			default:
				sc.devices = append(sc.devices, d)
				byPlatform[d.platform]++
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	sc.view.Devices = len(sc.devices)
	for _, p := range devicePlatforms {
		if byPlatform[p] > 0 {
			sc.view.ByPlatform = append(sc.view.ByPlatform, PlatformCount{Platform: p, Count: byPlatform[p]})
		}
	}
	slices.SortFunc(sc.view.Skipped, func(a, b SkipCount) int { return slices.Index(skipOrder, a.Reason) - slices.Index(skipOrder, b.Reason) })
	return sc, nil
}

// resolveAll checks a Patch all's targets and resolves them; the caller must
// be able to install and restart in the scope.
func (s *Service) resolveAll(ctx context.Context, c access.Caller, t Targets) (*scope, error) {
	if len(t.DeviceIDs) > 0 {
		return nil, apperr.Invalid("deviceIds", "Choose devices, or every device of an organization or site, not both.")
	}
	sc, err := s.resolveTargets(ctx, c, ScopeQuery{OrganizationID: t.OrganizationID, SiteID: t.SiteID}, t.Platforms)
	if err != nil {
		return nil, err
	}
	if !sc.view.CanManage {
		return nil, apperr.Forbidden()
	}
	return sc, nil
}

// checkTargets refuses a scope's fields on a request for chosen devices.
func (t Targets) checkTargets() error {
	if !t.All && (t.OrganizationID != uuid.Nil || t.SiteID != uuid.Nil || len(t.Platforms) > 0) {
		return apperr.Invalid("all", "An organization, a site or platforms go with every device of the scope (all).")
	}
	return nil
}

// where names a scope for people and the audit trail: "Acme" or
// "Acme / Head office".
func (v ScopeView) where() string {
	if v.SiteName == "" {
		return v.OrganizationName
	}
	return v.OrganizationName + " / " + v.SiteName
}

// skippedDetails is the left-out counts for the audit trail.
func (v ScopeView) skippedDetails() map[string]any {
	out := map[string]any{}
	for _, s := range v.Skipped {
		out[s.Reason] = s.Count
	}
	return out
}

// patchAllBatch is how many devices a Patch all sends the engine at once.
// The engine starts a bulk request's jobs one after another, each with its
// own install preview and commit (EndpointEndpoints.BulkAsync,
// JobService.CreateAsync), and EasyRMM waits 30 seconds for an answer: a
// batch of 200 answers well within that, where 1,000 may not.
const patchAllBatch = 200

// Batch is one request of a Patch all to the engine.
type Batch struct {
	Devices int `json:"devices"`
	// Sent counts the devices the engine started a job for.
	Sent int `json:"sent"`
	// Error says why the engine did not take the batch, or why it was not
	// sent; Unknown, that the engine did not answer, so whether it took the
	// batch is not known.
	Error   string `json:"error,omitempty"`
	Unknown bool   `json:"unknown,omitempty"`
}

// requestEnded is a batch's devices once the request ended before it went.
const requestEnded = "Not sent: the request ended before this batch was sent."

// batches sends devices to the engine at most batchSize at a time. A batch
// the engine does not take is recorded, its devices reported as not sent
// (or not known, when it did not answer), and the next batch still goes. A
// batch is sent, and what it started saved (after), whatever becomes of the
// request; once the request has ended, no further batch goes. The error is
// EasyRMM's own (the audit trail).
func (s *Service) batches(ctx context.Context, c access.Caller, devices []deviceRow, res *ActionResult, action string, details map[string]any,
	send func(ctx context.Context, ids []uuid.UUID) (BulkResult, error),
	after func(ctx context.Context, part []deviceRow, items []ActionItem) error) ([]Batch, error) {
	out := []Batch{}
	var failed error
	for lo := 0; lo < len(devices); lo += s.batchSize {
		part := devices[lo:min(lo+s.batchSize, len(devices))]
		b := Batch{Devices: len(part)}
		if ctx.Err() != nil {
			b.Error = "The request ended before this batch was sent."
			for _, d := range part {
				res.add(ActionItem{DeviceID: d.id, DeviceName: d.name, Message: requestEnded})
			}
			out = append(out, b)
			continue
		}
		b, err := s.batch(ctx, c, part, res, action, details, send, after)
		if err != nil && failed == nil {
			failed = err
		}
		out = append(out, b)
	}
	return out, failed
}

// batch sends one batch, and saves what it started.
func (s *Service) batch(ctx context.Context, c access.Caller, part []deviceRow, res *ActionResult, action string, details map[string]any,
	send func(ctx context.Context, ids []uuid.UUID) (BulkResult, error),
	after func(ctx context.Context, part []deviceRow, items []ActionItem) error) (Batch, error) {
	ctx, cancel := detached(ctx)
	defer cancel()
	ids := make([]uuid.UUID, 0, len(part))
	for _, d := range part {
		ids = append(ids, *d.endpointID)
	}
	b := Batch{Devices: len(part)}
	br, err := send(s.as(ctx, c, RoleAdmin, orgsOf(part)...), ids)
	if err != nil {
		s.noteError(err)
		b.Error = message(epError(err))
		msg := "Not sent: the patching engine refused this batch (" + cut(b.Error, 300) + ")."
		var ee *Error
		if !errors.As(err, &ee) || ee.Status < 400 || ee.Status >= 500 {
			b.Unknown = true
			msg = "Not known: the patching engine did not answer for this batch (" + cut(b.Error, 300) + "); see Jobs before sending it again."
		}
		for _, d := range part {
			res.add(ActionItem{DeviceID: d.id, DeviceName: d.name, Message: msg})
		}
		return b, nil
	}
	before, start := res.Succeeded, len(res.Results)
	err = s.settle(ctx, c, part, br, res, action, details)
	if after != nil {
		err = errors.Join(err, after(ctx, part, res.Results[start:]))
	}
	b.Sent = res.Succeeded - before
	return b, err
}

// batchDetails is a Patch all's batches for the audit trail.
func batchDetails(bs []Batch) []map[string]any {
	out := make([]map[string]any, 0, len(bs))
	for _, b := range bs {
		m := map[string]any{"devices": b.Devices, "sent": b.Sent}
		if b.Error != "" {
			m["error"] = b.Error
		}
		if b.Unknown {
			m["unknown"] = true
		}
		out = append(out, m)
	}
	return out
}

// platformText names platforms for the audit trail.
func platformText(ps []string) string {
	if len(ps) == 0 {
		return "every platform"
	}
	sorted := slices.Clone(ps)
	slices.SortFunc(sorted, func(a, b string) int { return slices.Index(devicePlatforms, a) - slices.Index(devicePlatforms, b) })
	return strings.Join(slices.Compact(sorted), ", ")
}
