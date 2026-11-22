package tenancy

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/docs"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// The customer record's details on organizations and sites (ADR-0066):
// doc.manage writes them, as a whole, and the audit log records which
// fields changed, never their values.

// normalizeHours checks a schedule and gives it as stored: nil for none,
// including one without a single interval.
func normalizeHours(f apperr.Fields, h *docs.Hours) *docs.Hours {
	if h == nil {
		return nil
	}
	open, problem := h.Normalize()
	f.Check(problem == "", "businessHours", problem)
	if !open {
		return nil
	}
	return h
}

func (in *OrganizationDetails) normalize() error {
	in.MainPhone, in.MainEmail = docs.CleanLine(in.MainPhone), docs.CleanLine(in.MainEmail)
	in.AfterHoursNote = docs.CleanText(in.AfterHoursNote)
	f := apperr.Fields{}
	f.Check(docs.ValidPhone(in.MainPhone), "mainPhone", "Enter a phone number of at most 50 characters, with its digits.")
	f.Check(docs.ValidEmail(in.MainEmail), "mainEmail", "Enter one email address, such as help@example.com.")
	website, ok := docs.NormalizeWebsite(docs.CleanLine(in.Website))
	f.Check(ok, "website", "Enter a web address, such as https://example.com.")
	in.Website = website
	in.BusinessHours = normalizeHours(f, in.BusinessHours)
	f.Check(utf8.RuneCountInString(in.AfterHoursNote) <= docs.MaxAfterHoursNote, "afterHoursNote", "Use at most 2,000 characters.")
	return f.Err()
}

func (in *SiteDetails) normalize() error {
	in.Address = docs.CleanText(in.Address)
	in.AddressLine1, in.AddressLine2 = docs.CleanLine(in.AddressLine1), docs.CleanLine(in.AddressLine2)
	in.City, in.Region, in.PostalCode = docs.CleanLine(in.City), docs.CleanLine(in.Region), docs.CleanLine(in.PostalCode)
	in.CountryCode = strings.ToUpper(docs.CleanLine(in.CountryCode))
	in.AfterHoursNote = docs.CleanText(in.AfterHoursNote)
	f := apperr.Fields{}
	f.Check(utf8.RuneCountInString(in.Address) <= MaxAddressLength, "address", "The address is limited to 1,000 characters.")
	f.Check(utf8.RuneCountInString(in.AddressLine1) <= docs.MaxAddressLine, "addressLine1", "Use at most 200 characters.")
	f.Check(utf8.RuneCountInString(in.AddressLine2) <= docs.MaxAddressLine, "addressLine2", "Use at most 200 characters.")
	f.Check(utf8.RuneCountInString(in.City) <= docs.MaxCityLength, "city", "Use at most 100 characters.")
	f.Check(utf8.RuneCountInString(in.Region) <= docs.MaxRegionLength, "region", "Use at most 100 characters.")
	f.Check(utf8.RuneCountInString(in.PostalCode) <= docs.MaxPostalCode, "postalCode", "Use at most 20 characters.")
	f.Check(in.CountryCode == "" || docs.ValidCountry(in.CountryCode), "countryCode", "Choose a country from the list.")
	in.BusinessHours = normalizeHours(f, in.BusinessHours)
	f.Check(utf8.RuneCountInString(in.AfterHoursNote) <= docs.MaxAfterHoursNote, "afterHoursNote", "Use at most 2,000 characters.")
	return f.Err()
}

// hoursJSON is a schedule as the database keeps it: NULL for none.
func hoursJSON(h *docs.Hours) ([]byte, error) {
	if h == nil {
		return nil, nil
	}
	return json.Marshal(h)
}

// field is one detail before and after a change, by its API name.
type field struct {
	name          string
	before, after any
}

// changedFields lists the names of the fields whose values differ, in the
// order given.
func changedFields(fields ...field) []string {
	var out []string
	for _, f := range fields {
		a, errA := json.Marshal(f.before)
		b, errB := json.Marshal(f.after)
		if errA != nil || errB != nil || string(a) != string(b) {
			out = append(out, f.name)
		}
	}
	return out
}

// UpdateOrganizationDetails replaces an organization's contact information
// and business hours. A change that changes nothing is not recorded.
func (s *Service) UpdateOrganizationDetails(ctx context.Context, c access.Caller, id uuid.UUID, in OrganizationDetails) (*Organization, error) {
	if _, err := s.GetOrganization(ctx, c, id); err != nil {
		return nil, err
	}
	if err := c.Require(rbac.PermDocManage, rbac.Org(id)); err != nil {
		return nil, err
	}
	if err := in.normalize(); err != nil {
		return nil, err
	}
	hours, err := hoursJSON(in.BusinessHours)
	if err != nil {
		return nil, err
	}
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		cur, err := scanOrg(tx.QueryRow(ctx, `SELECT `+orgColumns+` FROM organizations o WHERE o.id = $1 FOR NO KEY UPDATE`, id))
		if err != nil {
			return err
		}
		was := cur.OrganizationDetails
		fields := changedFields(
			field{"mainPhone", was.MainPhone, in.MainPhone}, field{"mainEmail", was.MainEmail, in.MainEmail},
			field{"website", was.Website, in.Website}, field{"businessHours", was.BusinessHours, in.BusinessHours},
			field{"afterHoursNote", was.AfterHoursNote, in.AfterHoursNote})
		if len(fields) == 0 {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE organizations SET main_phone = $2, main_email = $3, website = $4, business_hours = $5,
			after_hours_note = $6 WHERE id = $1`, id, in.MainPhone, in.MainEmail, in.Website, hours, in.AfterHoursNote); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "organization.details_update", Outcome: audit.Success,
			OrganizationID: id, TargetType: "organization", TargetID: id.String(), Details: map[string]any{"fields": fields}})
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	if err != nil {
		return nil, err
	}
	return s.GetOrganization(ctx, c, id)
}

// UpdateSiteDetails replaces a site's address and business hours. A change
// that changes nothing is not recorded.
func (s *Service) UpdateSiteDetails(ctx context.Context, c access.Caller, id uuid.UUID, in SiteDetails) (*Site, error) {
	site, err := s.GetSite(ctx, c, id)
	if err != nil {
		return nil, err
	}
	if err := c.Require(rbac.PermDocManage, rbac.Site(site.OrganizationID, id)); err != nil {
		return nil, err
	}
	if err := in.normalize(); err != nil {
		return nil, err
	}
	hours, err := hoursJSON(in.BusinessHours)
	if err != nil {
		return nil, err
	}
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		cur, err := scanSite(tx.QueryRow(ctx, `SELECT `+siteColumns+` FROM sites s JOIN organizations o ON o.id = s.organization_id
			WHERE s.id = $1 FOR NO KEY UPDATE OF s`, id))
		if err != nil {
			return err
		}
		was := cur.SiteDetails
		fields := changedFields(
			field{"address", was.Address, in.Address}, field{"addressLine1", was.AddressLine1, in.AddressLine1},
			field{"addressLine2", was.AddressLine2, in.AddressLine2}, field{"city", was.City, in.City},
			field{"region", was.Region, in.Region}, field{"postalCode", was.PostalCode, in.PostalCode},
			field{"countryCode", was.CountryCode, in.CountryCode}, field{"businessHours", was.BusinessHours, in.BusinessHours},
			field{"afterHoursNote", was.AfterHoursNote, in.AfterHoursNote})
		if len(fields) == 0 {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE sites SET address = $2, address_line1 = $3, address_line2 = $4, city = $5, region = $6,
			postal_code = $7, country_code = $8, business_hours = $9, after_hours_note = $10 WHERE id = $1`,
			id, in.Address, in.AddressLine1, in.AddressLine2, in.City, in.Region, in.PostalCode, in.CountryCode,
			hours, in.AfterHoursNote); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "site.details_update", Outcome: audit.Success,
			OrganizationID: site.OrganizationID, SiteID: id, TargetType: "site", TargetID: id.String(),
			Details: map[string]any{"fields": fields}})
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	if err != nil {
		return nil, err
	}
	return s.GetSite(ctx, c, id)
}
