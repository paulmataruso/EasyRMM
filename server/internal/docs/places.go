package docs

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// PlaceKinds are the kinds of place, from the largest.
var PlaceKinds = []string{"building", "floor", "room", "rack", "other"}

// Place is somewhere within a site: a building, a floor, a room, a rack or
// another place, inside another place of the same site (ParentID) or at the
// top of the site, at most four deep. The requirement's "customer
// locations" are the sites; places are where inside them.
type Place struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"organizationId"`
	SiteID         uuid.UUID  `json:"siteId"`
	ParentID       *uuid.UUID `json:"parentId"`
	Kind           string     `json:"kind"`
	Name           string     `json:"name"`
	// Depth is 1 at the top of the site.
	Depth     int       `json:"depth"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// PlaceInput is a new place; ParentID absent puts it at the top of the
// site.
type PlaceInput struct {
	ParentID *uuid.UUID `json:"parentId"`
	Kind     string     `json:"kind"`
	Name     string     `json:"name"`
}

// OptionalID is an identifier a patch may set, clear (null) or leave out.
type OptionalID struct {
	Set bool
	ID  *uuid.UUID
}

// UnmarshalJSON records that the field was given, null included.
func (o *OptionalID) UnmarshalJSON(b []byte) error {
	o.Set = true
	if bytes.Equal(b, []byte("null")) {
		o.ID = nil
		return nil
	}
	var id uuid.UUID
	if err := json.Unmarshal(b, &id); err != nil {
		return err
	}
	o.ID = &id
	return nil
}

// PlacePatch changes the fields it names. A new parent moves the place,
// with the places inside it, within its site; null moves it to the top.
type PlacePatch struct {
	ParentID OptionalID `json:"parentId"`
	Kind     *string    `json:"kind"`
	Name     *string    `json:"name"`
}

const placeColumns = `id, organization_id, site_id, parent_id, kind, name, depth, created_at, updated_at`

func scanPlace(row pgx.Row) (Place, error) {
	var p Place
	var depth int16
	err := row.Scan(&p.ID, &p.OrganizationID, &p.SiteID, &p.ParentID, &p.Kind, &p.Name, &depth, &p.CreatedAt, &p.UpdatedAt)
	p.Depth = int(depth)
	return p, err
}

func checkPlace(kind, name string) error {
	f := apperr.Fields{}
	f.Check(slices.Contains(PlaceKinds, kind), "kind", "Choose building, floor, room, rack or other.")
	f.Check(name != "", "name", "Enter a name.")
	f.Check(!tooLong(name, MaxNameLength), "name", "Use at most 200 characters.")
	return f.Err()
}

// mapPlaceWriteError turns the database's refusals into what people can
// act on.
func mapPlaceWriteError(err error) error {
	switch {
	case database.IsUniqueViolation(err) && database.ConstraintName(err) == "site_places_name_key":
		return apperr.Invalid("name", "There is already a place with this name here.")
	case database.IsForeignKeyViolation(err) && database.ConstraintName(err) == "site_places_site_id_parent_id_parent_depth_fkey":
		// A parent went, or moved, under this write: only a writer that
		// skips the lock on the site, such as a restore, can do that.
		return errPlacesChanged
	}
	return err
}

var errPlacesChanged = apperr.Conflict("places_changed", "The places here changed at the same time. Reload and try again.")

// siteOf reads the organization of a site the caller can see.
func (s *Service) siteOf(ctx context.Context, c access.Caller, siteID uuid.UUID) (uuid.UUID, error) {
	var org uuid.UUID
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT organization_id FROM sites WHERE id = $1`, siteID).Scan(&org)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, apperr.NotFound()
	}
	return org, err
}

// ListPlaces returns a site's places in the order of their tree: each
// place followed by the places inside it, by name.
func (s *Service) ListPlaces(ctx context.Context, c access.Caller, siteID uuid.UUID) ([]Place, error) {
	org, err := s.siteOf(ctx, c, siteID)
	if err != nil {
		return nil, err
	}
	if err := c.Require(rbac.PermDocView, rbac.Site(org, siteID)); err != nil {
		return nil, err
	}
	var all []Place
	err = s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+placeColumns+` FROM site_places WHERE site_id = $1`, siteID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			p, err := scanPlace(rows)
			if err != nil {
				return err
			}
			all = append(all, p)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return treeOrder(all), nil
}

// treeOrder puts places in the order of their tree.
func treeOrder(all []Place) []Place {
	children := map[uuid.UUID][]Place{}
	for _, p := range all {
		var parent uuid.UUID
		if p.ParentID != nil {
			parent = *p.ParentID
		}
		children[parent] = append(children[parent], p)
	}
	out := make([]Place, 0, len(all))
	var walk func(parent uuid.UUID)
	walk = func(parent uuid.UUID) {
		list := children[parent]
		slices.SortFunc(list, func(a, b Place) int {
			return cmp.Or(cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)), bytes.Compare(a.ID[:], b.ID[:]))
		})
		for _, p := range list {
			out = append(out, p)
			walk(p.ID)
		}
	}
	walk(uuid.Nil)
	return out
}

func (s *Service) getPlace(ctx context.Context, c access.Caller, id uuid.UUID) (*Place, error) {
	var p Place
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var err error
		p, err = scanPlace(tx.QueryRow(ctx, `SELECT `+placeColumns+` FROM site_places WHERE id = $1`, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	if err != nil {
		return nil, err
	}
	if err := c.Require(rbac.PermDocView, rbac.Site(p.OrganizationID, p.SiteID)); err != nil {
		return nil, err
	}
	return &p, nil
}

// parentDepth reads the depth of a place of the site, to put another
// inside it.
func parentDepth(ctx context.Context, tx pgx.Tx, siteID, parentID uuid.UUID) (int, error) {
	var depth int16
	err := tx.QueryRow(ctx, `SELECT depth FROM site_places WHERE id = $1 AND site_id = $2`, parentID, siteID).Scan(&depth)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, apperr.Invalid("parentId", "Choose a place of this site.")
	}
	return int(depth), err
}

var errTooDeep = apperr.Invalid("parentId", "Places go at most four deep: a building, a floor, a room and a rack, for example.")

func placeEvent(c access.Caller, action string, p *Place, details map[string]any) audit.Event {
	return audit.Event{Actor: c.Actor, Action: action, Outcome: audit.Success, OrganizationID: p.OrganizationID, SiteID: p.SiteID,
		TargetType: "site_place", TargetID: p.ID.String(), Details: details}
}

// placeDetails are an audit record's details: the kind and the parent's
// ID, never the name.
func placeDetails(kind string, parent *uuid.UUID) map[string]any {
	d := map[string]any{"kind": kind}
	if parent != nil {
		d["parentId"] = parent.String()
	}
	return d
}

// CreatePlace adds a place to a site.
func (s *Service) CreatePlace(ctx context.Context, c access.Caller, siteID uuid.UUID, in PlaceInput) (*Place, error) {
	org, err := s.siteOf(ctx, c, siteID)
	if err != nil {
		return nil, err
	}
	if err := c.Require(rbac.PermDocManage, rbac.Site(org, siteID)); err != nil {
		return nil, err
	}
	in.Name = CleanLine(in.Name)
	if err := checkPlace(in.Kind, in.Name); err != nil {
		return nil, err
	}
	var id uuid.UUID
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		if err := lockLevel(ctx, tx, org, &siteID); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM site_places WHERE site_id = $1`, siteID).Scan(&n); err != nil {
			return err
		}
		if n >= MaxPlacesPerSite {
			return apperr.Conflict("too_many_places", "This site already has 500 places, the most a site can have.")
		}
		depth := 1
		if in.ParentID != nil {
			d, err := parentDepth(ctx, tx, siteID, *in.ParentID)
			if err != nil {
				return err
			}
			if depth = d + 1; depth > MaxPlaceDepth {
				return errTooDeep
			}
		}
		if err := tx.QueryRow(ctx, `INSERT INTO site_places (organization_id, site_id, parent_id, depth, kind, name)
			VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`, org, siteID, in.ParentID, depth, in.Kind, in.Name).Scan(&id); err != nil {
			return err
		}
		p := &Place{ID: id, OrganizationID: org, SiteID: siteID}
		return s.audit.Write(ctx, tx, placeEvent(c, "site_place.create", p, placeDetails(in.Kind, in.ParentID)))
	})
	if err != nil {
		return nil, mapPlaceWriteError(err)
	}
	return s.getPlace(ctx, c, id)
}

// apply sets what a patch names; the rest is the place's.
func (p PlacePatch) apply(cur *Place) (kind, name string, parent *uuid.UUID) {
	kind, name, parent = cur.Kind, cur.Name, cur.ParentID
	if p.Kind != nil {
		kind = *p.Kind
	}
	if p.Name != nil {
		name = CleanLine(*p.Name)
	}
	if p.ParentID.Set {
		parent = p.ParentID.ID
	}
	return kind, name, parent
}

// check checks the kind and the name the place would have.
func (p PlacePatch) check(cur *Place) error {
	kind, name, _ := p.apply(cur)
	return checkPlace(kind, name)
}

// UpdatePlace renames a place, changes its kind, or moves it with the
// places inside it to another place of its site or to the top. The patch
// is applied to the place as it is once its site is locked, so a move made
// since the caller read it is built on, not undone. A change that changes
// nothing is not recorded.
func (s *Service) UpdatePlace(ctx context.Context, c access.Caller, id uuid.UUID, p PlacePatch) (*Place, error) {
	cur, err := s.getPlace(ctx, c, id)
	if err != nil {
		return nil, err
	}
	if err := c.Require(rbac.PermDocManage, rbac.Site(cur.OrganizationID, cur.SiteID)); err != nil {
		return nil, err
	}
	// The kind and the name are checked each on its own, so a patch that
	// passes here passes on the place as it is once locked; a refusal takes
	// no lock.
	if err := p.check(cur); err != nil {
		return nil, err
	}
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		// A place never leaves its site.
		if err := lockLevel(ctx, tx, cur.OrganizationID, &cur.SiteID); err != nil {
			return err
		}
		locked, err := scanPlace(tx.QueryRow(ctx, `SELECT `+placeColumns+` FROM site_places WHERE id = $1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		kind, name, parent := p.apply(&locked)
		var fields []string
		if kind != locked.Kind {
			fields = append(fields, "kind")
		}
		if name != locked.Name {
			fields = append(fields, "name")
		}
		if !sameID(parent, locked.ParentID) {
			fields = append(fields, "parentId")
			if err := movePlace(ctx, tx, &locked, parent); err != nil {
				return err
			}
		}
		if len(fields) == 0 {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE site_places SET kind = $2, name = $3 WHERE id = $1`, id, kind, name); err != nil {
			return err
		}
		d := placeDetails(kind, parent)
		d["fields"] = fields
		return s.audit.Write(ctx, tx, placeEvent(c, "site_place.update", cur, d))
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	if err != nil {
		return nil, mapPlaceWriteError(err)
	}
	return s.getPlace(ctx, c, id)
}

// movePlace puts a place, and the places inside it, under parent (nil:
// the top of the site), in one statement, so that the database's key on
// each place's parent and depth holds at its end.
func movePlace(ctx context.Context, tx pgx.Tx, cur *Place, parent *uuid.UUID) error {
	depth := 1
	if parent != nil {
		var inside bool
		if err := tx.QueryRow(ctx, `WITH RECURSIVE sub AS (
				SELECT id FROM site_places WHERE id = $1
				UNION ALL
				SELECT p.id FROM site_places p JOIN sub ON p.parent_id = sub.id)
			SELECT EXISTS (SELECT 1 FROM sub WHERE id = $2)`, cur.ID, *parent).Scan(&inside); err != nil {
			return err
		}
		if inside {
			return apperr.Invalid("parentId", "A place cannot go inside itself or a place within it.")
		}
		d, err := parentDepth(ctx, tx, cur.SiteID, *parent)
		if err != nil {
			return err
		}
		depth = d + 1
	}
	shift := depth - cur.Depth
	var deepest int16
	if err := tx.QueryRow(ctx, `WITH RECURSIVE sub AS (
			SELECT id, depth FROM site_places WHERE id = $1
			UNION ALL
			SELECT p.id, p.depth FROM site_places p JOIN sub ON p.parent_id = sub.id)
		SELECT max(depth) FROM sub`, cur.ID).Scan(&deepest); err != nil {
		return err
	}
	if int(deepest)+shift > MaxPlaceDepth {
		return errTooDeep
	}
	_, err := tx.Exec(ctx, `WITH RECURSIVE sub AS (
			SELECT id FROM site_places WHERE id = $1
			UNION ALL
			SELECT p.id FROM site_places p JOIN sub ON p.parent_id = sub.id)
		UPDATE site_places SET depth = depth + $3,
			parent_id = CASE WHEN id = $1 THEN $2 ELSE parent_id END
		WHERE id IN (SELECT id FROM sub)`, cur.ID, parent, shift)
	return err
}

func sameID(a, b *uuid.UUID) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

// DeletePlace removes a place that has no places inside it.
func (s *Service) DeletePlace(ctx context.Context, c access.Caller, id uuid.UUID) error {
	cur, err := s.getPlace(ctx, c, id)
	if err != nil {
		return err
	}
	if err := c.Require(rbac.PermDocManage, rbac.Site(cur.OrganizationID, cur.SiteID)); err != nil {
		return err
	}
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		if err := lockLevel(ctx, tx, cur.OrganizationID, &cur.SiteID); err != nil {
			return err
		}
		var inner bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM site_places WHERE parent_id = $1)`, id).Scan(&inner); err != nil {
			return err
		}
		if inner {
			return apperr.Conflict("place_not_empty", "Delete or move the places inside this one first.")
		}
		tag, err := tx.Exec(ctx, `DELETE FROM site_places WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return s.audit.Write(ctx, tx, placeEvent(c, "site_place.delete", cur, placeDetails(cur.Kind, cur.ParentID)))
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return apperr.NotFound()
	}
	return err
}
