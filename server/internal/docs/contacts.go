package docs

import (
	"context"
	"encoding/base64"
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

// Contact priorities.
const (
	PriorityPrimary   = "primary"
	PrioritySecondary = "secondary"
	PriorityNone      = "none"
)

// Contact is one of a customer's staff: not an EasyRMM account, and
// personal data. A contact belongs to the organization, or to one of its
// sites (SiteID).
type Contact struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"organizationId"`
	SiteID         *uuid.UUID `json:"siteId"`
	// SiteName names the site, empty for the organization's own.
	SiteName    string `json:"siteName"`
	Name        string `json:"name"`
	JobTitle    string `json:"jobTitle"`
	Email       string `json:"email"`
	OfficePhone string `json:"officePhone"`
	MobilePhone string `json:"mobilePhone"`
	Note        string `json:"note"`
	// Priority is primary, secondary or none: at most one primary at the
	// organization's level and one per site.
	Priority string `json:"priority"`
	// Emergency marks whom to call in an emergency, whatever the priority.
	Emergency bool      `json:"emergency"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	// CanManage tells the client whether the caller may change it.
	CanManage bool `json:"canManage"`
}

// ContactInput is a new contact. SiteID is the site it belongs to, or
// absent for the organization's own.
type ContactInput struct {
	SiteID      *uuid.UUID `json:"siteId"`
	Name        string     `json:"name"`
	JobTitle    string     `json:"jobTitle"`
	Email       string     `json:"email"`
	OfficePhone string     `json:"officePhone"`
	MobilePhone string     `json:"mobilePhone"`
	Note        string     `json:"note"`
	Priority    string     `json:"priority"`
	Emergency   bool       `json:"emergency"`
}

// ContactPatch changes the fields it names. A contact stays where it is:
// one who moves to another site is a new contact there.
type ContactPatch struct {
	Name        *string `json:"name"`
	JobTitle    *string `json:"jobTitle"`
	Email       *string `json:"email"`
	OfficePhone *string `json:"officePhone"`
	MobilePhone *string `json:"mobilePhone"`
	Note        *string `json:"note"`
	Priority    *string `json:"priority"`
	Emergency   *bool   `json:"emergency"`
}

// contactFields are a contact's editable values, in their API names.
type contactFields struct {
	name, jobTitle, email, officePhone, mobilePhone, note, priority string
	emergency                                                       bool
}

func (f *contactFields) clean() {
	f.name, f.jobTitle, f.email = CleanLine(f.name), CleanLine(f.jobTitle), CleanLine(f.email)
	f.officePhone, f.mobilePhone, f.note = CleanLine(f.officePhone), CleanLine(f.mobilePhone), CleanText(f.note)
	if f.priority == "" {
		f.priority = PriorityNone
	}
}

func (f *contactFields) check() error {
	e := apperr.Fields{}
	e.Check(f.name != "", "name", "Enter the contact's name.")
	e.Check(!tooLong(f.name, MaxNameLength), "name", "Use at most 200 characters.")
	e.Check(!tooLong(f.jobTitle, MaxNameLength), "jobTitle", "Use at most 200 characters.")
	e.Check(ValidEmail(f.email), "email", "Enter one email address, such as help@example.com.")
	e.Check(ValidPhone(f.officePhone), "officePhone", "Enter a phone number of at most 50 characters, with its digits.")
	e.Check(ValidPhone(f.mobilePhone), "mobilePhone", "Enter a phone number of at most 50 characters, with its digits.")
	e.Check(!tooLong(f.note, MaxNoteLength), "note", "Use at most 2,000 characters.")
	e.Check(slices.Contains([]string{PriorityPrimary, PrioritySecondary, PriorityNone}, f.priority), "priority", "Choose primary, secondary or none.")
	return e.Err()
}

// changed lists the fields that differ from before, in their API names.
func (f contactFields) changed(before contactFields) []string {
	var out []string
	for _, c := range []struct {
		name string
		same bool
	}{
		{"name", f.name == before.name}, {"jobTitle", f.jobTitle == before.jobTitle}, {"email", f.email == before.email},
		{"officePhone", f.officePhone == before.officePhone}, {"mobilePhone", f.mobilePhone == before.mobilePhone},
		{"note", f.note == before.note}, {"priority", f.priority == before.priority}, {"emergency", f.emergency == before.emergency},
	} {
		if !c.same {
			out = append(out, c.name)
		}
	}
	return out
}

func (c *Contact) fields() contactFields {
	return contactFields{c.Name, c.JobTitle, c.Email, c.OfficePhone, c.MobilePhone, c.Note, c.Priority, c.Emergency}
}

const contactColumns = `c.id, c.organization_id, c.site_id, coalesce(s.name, ''), c.name, c.job_title, c.email,
	c.office_phone, c.mobile_phone, c.note, c.priority, c.emergency, c.created_at, c.updated_at`

const contactFrom = ` FROM contacts c LEFT JOIN sites s ON s.id = c.site_id`

// scanContact reads contactColumns, then any further columns into extra.
func scanContact(row pgx.Row, extra ...any) (Contact, error) {
	var x Contact
	err := row.Scan(append([]any{&x.ID, &x.OrganizationID, &x.SiteID, &x.SiteName, &x.Name, &x.JobTitle, &x.Email,
		&x.OfficePhone, &x.MobilePhone, &x.Note, &x.Priority, &x.Emergency, &x.CreatedAt, &x.UpdatedAt}, extra...)...)
	return x, err
}

// contactOrder is the order of a list of contacts: the organization's own
// first, then each site's by name; at each, the primary, the secondary,
// then the rest by name.
const contactOrder = `c.site_id IS NOT NULL, lower(coalesce(s.name, '')), coalesce(c.site_id, '00000000-0000-0000-0000-000000000000'::uuid),
	CASE c.priority WHEN 'primary' THEN 0 WHEN 'secondary' THEN 1 ELSE 2 END, lower(c.name), c.id`

// contactCursor is where a page of contacts ends: the last row's
// contactOrder.
type contactCursor struct {
	AtSite   bool      `json:"a"`
	SiteName string    `json:"s"`
	SiteID   uuid.UUID `json:"i"`
	Rank     int       `json:"r"`
	Name     string    `json:"n"`
	ID       uuid.UUID `json:"c"`
}

func (k contactCursor) encode() string {
	b, _ := json.Marshal(k)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeContactCursor(s string) (*contactCursor, error) {
	k := &contactCursor{}
	if s == "" {
		return k, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err == nil {
		err = json.Unmarshal(b, k)
	}
	if err != nil {
		return nil, apperr.Invalid("after", "is not a valid cursor")
	}
	return k, nil
}

// ContactQuery chooses a page of an organization's contacts.
type ContactQuery struct {
	// SiteID limits the list to one site's contacts; uuid.Nil lists the
	// organization's own and every site's.
	SiteID uuid.UUID
	// Key keeps the primary and the emergency contacts only, for the
	// organization's overview.
	Key bool
	// After is the Next of the page before; empty for the first.
	After string
	// Limit is the most contacts a page holds.
	Limit int
}

// visibleLevel checks that the organization, and the site when one is
// given, are visible to the caller and that the site is the
// organization's. Either missing is not found.
func (s *Service) visibleLevel(ctx context.Context, c access.Caller, orgID uuid.UUID, siteID *uuid.UUID) error {
	return s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM organizations WHERE id = $1)
			AND ($2::uuid IS NULL OR EXISTS (SELECT 1 FROM sites WHERE id = $2 AND organization_id = $1))`, orgID, siteID).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return apperr.NotFound()
		}
		return nil
	})
}

// ListContacts returns a page of an organization's contacts that the
// caller may read, in contactOrder, and the cursor of the next page, empty
// after the last. An organization's own contacts number at most 1,000, so
// a first page of 1,000 holds them all.
func (s *Service) ListContacts(ctx context.Context, c access.Caller, orgID uuid.UUID, q ContactQuery) ([]Contact, string, error) {
	site := nullID(q.SiteID)
	if err := s.visibleLevel(ctx, c, orgID, site); err != nil {
		return nil, "", err
	}
	if site != nil {
		if err := c.Require(rbac.PermDocView, rbac.Site(orgID, q.SiteID)); err != nil {
			return nil, "", err
		}
	} else if !c.CanInOrg(rbac.PermDocView, orgID) {
		return nil, "", apperr.Forbidden()
	}
	after, err := decodeContactCursor(q.After)
	if err != nil {
		return nil, "", err
	}
	if q.Limit <= 0 || q.Limit > MaxContactsAtLevel {
		q.Limit = MaxContactsAtLevel
	}
	out := []Contact{}
	var next string
	err = s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+contactColumns+`, `+contactOrder+contactFrom+`
			WHERE c.organization_id = $1 AND ($2::uuid IS NULL OR c.site_id = $2)
			  AND ($3 = '' OR (`+contactOrder+`) > ($4::boolean, $5::text, $6::uuid, $7::int, $8::text, $9::uuid))
			  AND (NOT $11 OR c.priority = 'primary' OR c.emergency)
			ORDER BY `+contactOrder+` LIMIT $10`,
			orgID, site, q.After, after.AtSite, after.SiteName, after.SiteID, after.Rank, after.Name, after.ID, q.Limit+1, q.Key)
		if err != nil {
			return err
		}
		defer rows.Close()
		n := 0
		for rows.Next() {
			if n++; n > q.Limit {
				next = after.encode()
				break
			}
			x, err := scanContact(rows, &after.AtSite, &after.SiteName, &after.SiteID, &after.Rank, &after.Name, &after.ID)
			if err != nil {
				return err
			}
			// Row-level security shows what the caller's roles reach; a
			// role there without doc.view still reads none of it.
			where := level(x.OrganizationID, x.SiteID)
			if !c.Can(rbac.PermDocView, where) {
				continue
			}
			x.CanManage = c.Can(rbac.PermDocManage, where)
			out = append(out, x)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, "", err
	}
	return out, next, nil
}

// getContact reads a contact the caller may read.
func (s *Service) getContact(ctx context.Context, c access.Caller, id uuid.UUID) (*Contact, error) {
	var x Contact
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var err error
		x, err = scanContact(tx.QueryRow(ctx, `SELECT `+contactColumns+contactFrom+` WHERE c.id = $1`, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	if err != nil {
		return nil, err
	}
	where := level(x.OrganizationID, x.SiteID)
	if err := c.Require(rbac.PermDocView, where); err != nil {
		return nil, err
	}
	x.CanManage = c.Can(rbac.PermDocManage, where)
	return &x, nil
}

// lockLevel takes the organization's or the site's row for the rest of the
// transaction, so that writes at one level count and choose a primary one
// at a time.
func lockLevel(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, siteID *uuid.UUID) error {
	var err error
	if siteID == nil {
		_, err = tx.Exec(ctx, `SELECT 1 FROM organizations WHERE id = $1 FOR NO KEY UPDATE`, orgID)
	} else {
		_, err = tx.Exec(ctx, `SELECT 1 FROM sites WHERE id = $1 FOR NO KEY UPDATE`, *siteID)
	}
	return err
}

// demotePrimary makes the level's primary contact, other than except,
// secondary, and returns its ID, or nil when there was none.
func demotePrimary(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, siteID *uuid.UUID, except uuid.UUID) (*uuid.UUID, error) {
	var id uuid.UUID
	err := tx.QueryRow(ctx, `UPDATE contacts SET priority = 'secondary'
		WHERE organization_id = $1 AND site_id IS NOT DISTINCT FROM $2 AND priority = 'primary' AND id <> $3
		RETURNING id`, orgID, siteID, except).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &id, nil
}

// contactDetails are an audit record's details: identifiers and choices,
// never a name, an address, a number or a note (ADR-0066, "Audit").
func contactDetails(fields []string, f contactFields, demoted *uuid.UUID) map[string]any {
	d := map[string]any{"priority": f.priority, "emergency": f.emergency}
	if fields != nil {
		d["fields"] = fields
	}
	if demoted != nil {
		d["previousPrimaryId"] = demoted.String()
	}
	return d
}

func contactEvent(c access.Caller, action string, x *Contact, details map[string]any) audit.Event {
	e := audit.Event{Actor: c.Actor, Action: action, Outcome: audit.Success, OrganizationID: x.OrganizationID,
		TargetType: "contact", TargetID: x.ID.String(), Details: details}
	if x.SiteID != nil {
		e.SiteID = *x.SiteID
	}
	return e
}

// CreateContact adds a contact to the organization or one of its sites.
// Making it the primary contact makes the one before it secondary.
func (s *Service) CreateContact(ctx context.Context, c access.Caller, orgID uuid.UUID, in ContactInput) (*Contact, error) {
	if err := s.visibleLevel(ctx, c, orgID, in.SiteID); err != nil {
		return nil, err
	}
	if err := c.Require(rbac.PermDocManage, level(orgID, in.SiteID)); err != nil {
		return nil, err
	}
	f := contactFields{in.Name, in.JobTitle, in.Email, in.OfficePhone, in.MobilePhone, in.Note, in.Priority, in.Emergency}
	f.clean()
	if err := f.check(); err != nil {
		return nil, err
	}
	var id uuid.UUID
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		if err := lockLevel(ctx, tx, orgID, in.SiteID); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM contacts WHERE organization_id = $1 AND site_id IS NOT DISTINCT FROM $2`,
			orgID, in.SiteID).Scan(&n); err != nil {
			return err
		}
		if n >= MaxContactsAtLevel {
			return apperr.Conflict("too_many_contacts", "This already has 1,000 contacts, the most one organization or site can have.")
		}
		var demoted *uuid.UUID
		if f.priority == PriorityPrimary {
			var err error
			if demoted, err = demotePrimary(ctx, tx, orgID, in.SiteID, uuid.Nil); err != nil {
				return err
			}
		}
		err := tx.QueryRow(ctx, `INSERT INTO contacts (organization_id, site_id, name, job_title, email, office_phone, mobile_phone, note, priority, emergency)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`,
			orgID, in.SiteID, f.name, f.jobTitle, f.email, f.officePhone, f.mobilePhone, f.note, f.priority, f.emergency).Scan(&id)
		if err != nil {
			return err
		}
		set := f.changed(contactFields{priority: PriorityNone})
		x := &Contact{ID: id, OrganizationID: orgID, SiteID: in.SiteID}
		return s.audit.Write(ctx, tx, contactEvent(c, "contact.create", x, contactDetails(set, f, demoted)))
	})
	if err != nil {
		return nil, mapContactWriteError(err)
	}
	return s.getContact(ctx, c, id)
}

// apply sets the fields a patch names; the others keep their values.
func (p ContactPatch) apply(f contactFields) contactFields {
	for _, set := range []struct {
		from *string
		to   *string
	}{
		{p.Name, &f.name}, {p.JobTitle, &f.jobTitle}, {p.Email, &f.email}, {p.OfficePhone, &f.officePhone},
		{p.MobilePhone, &f.mobilePhone}, {p.Note, &f.note}, {p.Priority, &f.priority},
	} {
		if set.from != nil {
			*set.to = *set.from
		}
	}
	if p.Emergency != nil {
		f.emergency = *p.Emergency
	}
	f.clean()
	return f
}

// errPrimaryChanged answers a write that would make a second primary
// contact. The lock on the level rules that out among EasyRMM's own
// writes; only a write made in the database directly can cause it.
var errPrimaryChanged = apperr.Conflict("primary_changed", "Another contact became the primary one at the same time. Reload and try again.")

// mapContactWriteError turns the database's refusal of a second primary
// contact into a conflict.
func mapContactWriteError(err error) error {
	if database.IsUniqueViolation(err) && strings.HasPrefix(database.ConstraintName(err), "contacts_primary_") {
		return errPrimaryChanged
	}
	return err
}

// UpdateContact changes the fields a patch names. Making the contact the
// primary one makes the one before it secondary. The patch is applied to
// the contact as it is once its level is locked, so a change made since the
// caller read it is kept, not overwritten. A change that changes nothing is
// not recorded.
func (s *Service) UpdateContact(ctx context.Context, c access.Caller, id uuid.UUID, p ContactPatch) (*Contact, error) {
	cur, err := s.getContact(ctx, c, id)
	if err != nil {
		return nil, err
	}
	if err := c.Require(rbac.PermDocManage, level(cur.OrganizationID, cur.SiteID)); err != nil {
		return nil, err
	}
	// Each field is checked on its own, so a patch that passes here passes
	// on the contact as it is once locked; a refusal takes no lock.
	checked := p.apply(cur.fields())
	if err := checked.check(); err != nil {
		return nil, err
	}
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		// The level is the contact's for good: a contact never moves.
		if err := lockLevel(ctx, tx, cur.OrganizationID, cur.SiteID); err != nil {
			return err
		}
		locked, err := scanContact(tx.QueryRow(ctx, `SELECT `+contactColumns+contactFrom+` WHERE c.id = $1 FOR UPDATE OF c`, id))
		if err != nil {
			return err
		}
		before := locked.fields()
		f := p.apply(before)
		fields := f.changed(before)
		if len(fields) == 0 {
			return nil
		}
		var demoted *uuid.UUID
		if f.priority == PriorityPrimary && before.priority != PriorityPrimary {
			if demoted, err = demotePrimary(ctx, tx, cur.OrganizationID, cur.SiteID, id); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE contacts SET name = $2, job_title = $3, email = $4, office_phone = $5, mobile_phone = $6,
			note = $7, priority = $8, emergency = $9 WHERE id = $1`,
			id, f.name, f.jobTitle, f.email, f.officePhone, f.mobilePhone, f.note, f.priority, f.emergency); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, contactEvent(c, "contact.update", cur, contactDetails(fields, f, demoted)))
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	if err != nil {
		return nil, mapContactWriteError(err)
	}
	return s.getContact(ctx, c, id)
}

// DeleteContact removes a contact.
func (s *Service) DeleteContact(ctx context.Context, c access.Caller, id uuid.UUID) error {
	cur, err := s.getContact(ctx, c, id)
	if err != nil {
		return err
	}
	if err := c.Require(rbac.PermDocManage, level(cur.OrganizationID, cur.SiteID)); err != nil {
		return err
	}
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM contacts WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return s.audit.Write(ctx, tx, contactEvent(c, "contact.delete", cur, contactDetails(nil, cur.fields(), nil)))
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return apperr.NotFound()
	}
	return err
}

func nullID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}
