// Package docs keeps what an MSP knows about each customer
// (ADR-0066). This is the customer record: contacts at an organization or
// one of its sites, places within a site, and the rules for the
// organization's and sites' own details (contact information, addresses,
// business hours) that the tenancy package stores on their rows.
//
// Every query runs in the caller's row-level security scope; the policies
// keep each organization's rows to it and site-scoped people to their
// sites' rows. doc.view reads and doc.manage changes, each checked at the
// row's organization, or its site for a site's rows.
package docs

import (
	"context"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Field limits, matching the database's.
const (
	MaxNameLength      = 200
	MaxPhoneLength     = 50
	MaxEmailLength     = 254
	MaxWebsiteLength   = 2000
	MaxNoteLength      = 2000
	MaxAddressLine     = 200
	MaxCityLength      = 100
	MaxRegionLength    = 100
	MaxPostalCode      = 20
	MaxAfterHoursNote  = 2000
	MaxContactsAtLevel = 1000
	MaxPlacesPerSite   = 500
	MaxPlaceDepth      = 4
)

// Service keeps contacts and places.
type Service struct {
	db    *database.DB
	audit *audit.Logger
}

// New builds the service.
func New(db *database.DB, auditLog *audit.Logger) *Service {
	return &Service{db: db, audit: auditLog}
}

// level is where a row belongs: the organization, or one of its sites.
func level(org uuid.UUID, site *uuid.UUID) rbac.Resource {
	if site == nil {
		return rbac.Org(org)
	}
	return rbac.Site(org, *site)
}

// ---------------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------------

// CleanLine makes one line of text safe to store: tabs and line breaks
// become spaces, every other C0 control character goes, and surrounding
// space is trimmed. Search excerpts mark matches with control characters
// that stored text therefore never holds (ADR-0066, "Pages").
func CleanLine(s string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			return ' '
		case r < 0x20:
			return -1
		}
		return r
	}, s))
}

// CleanText makes text of several lines safe to store: carriage returns
// become line feeds (a CR LF pair one), every C0 control character but tab
// and line feed goes, and surrounding space is trimmed.
func CleanText(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		switch {
		case r == '\r':
			return '\n'
		case r == '\t' || r == '\n':
			return r
		case r < 0x20:
			return -1
		}
		return r
	}, s))
}

// tooLong reports whether s has more than n characters.
func tooLong(s string, n int) bool { return utf8.RuneCountInString(s) > n }

// ValidPhone reports whether s reads as a telephone number: empty, or at
// most 50 characters with at least one digit. Numbers are written in too
// many ways (extensions, letters, pauses) to check further.
func ValidPhone(s string) bool {
	return s == "" || (!tooLong(s, MaxPhoneLength) && strings.ContainsFunc(s, unicode.IsDigit))
}

// ValidEmail reports whether s is empty or one bare address, such as
// help@example.com, with a dot in its domain.
func ValidEmail(s string) bool {
	if s == "" {
		return true
	}
	if len(s) > MaxEmailLength || strings.ContainsAny(s, " <>\",;") {
		return false
	}
	addr, err := mail.ParseAddress(s)
	if err != nil || addr.Address != s {
		return false
	}
	at := strings.LastIndexByte(s, '@')
	return at > 0 && strings.Contains(s[at:], ".")
}

// NormalizeWebsite checks a website address and gives it as stored: an
// http or https URL with a host and no user name or password in it. An
// address typed without a scheme (example.com) is taken as https.
func NormalizeWebsite(s string) (string, bool) {
	if s == "" {
		return "", true
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	if len(s) > MaxWebsiteLength || strings.ContainsAny(s, " \\") {
		return s, false
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil {
		return s, false
	}
	return u.String(), true
}

// ---------------------------------------------------------------------------
// What a site or an organization holds
// ---------------------------------------------------------------------------

// Counts is how much documentation of each kind a site or an organization
// holds, by kind (CountKinds). Deleting one that holds any needs the
// person to confirm these numbers (ADR-0066, "Deleting an organization or
// a site").
type Counts map[string]int

// CountKinds are the kinds Counts counts.
var CountKinds = []string{"contacts", "places"}

// Total is the number of rows counted.
func (c Counts) Total() int {
	n := 0
	for _, v := range c {
		n += v
	}
	return n
}

// Matches reports whether c has the same number of each kind as other.
func (c Counts) Matches(other Counts) bool {
	for _, k := range CountKinds {
		if c[k] != other[k] {
			return false
		}
	}
	return true
}

// String says what was counted, for people: "2 contacts and 1 place".
func (c Counts) String() string {
	var parts []string
	for _, k := range CountKinds {
		switch n := c[k]; n {
		case 0:
		case 1:
			parts = append(parts, "1 "+strings.TrimSuffix(k, "s"))
		default:
			parts = append(parts, strconv.Itoa(n)+" "+k)
		}
	}
	switch len(parts) {
	case 0:
		return "nothing"
	case 1:
		return parts[0]
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}

// CheckDeletion lets a site or an organization (what) be deleted with the
// documentation it holds only when the request confirmed exactly that:
// without a confirmation, one that holds any is refused with
// documentation_exists and the counts; a confirmation that no longer
// matches is refused with documentation_changed and the counts now.
func CheckDeletion(what string, held, confirmed Counts) error {
	switch {
	case confirmed == nil && held.Total() == 0:
		return nil
	case confirmed == nil:
		return apperr.ConflictCounts("documentation_exists",
			"This "+what+" holds "+held.String()+", which would be deleted with it. Confirm to delete them too.", held)
	case !held.Matches(confirmed):
		return apperr.ConflictCounts("documentation_changed",
			"This "+what+"'s documentation changed after you confirmed: it now holds "+held.String()+". Confirm again.", held)
	}
	return nil
}

// SiteCounts counts what a site holds, in the caller's transaction, which
// must see the whole site (a caller who may delete it does).
func SiteCounts(ctx context.Context, tx pgx.Tx, siteID uuid.UUID) (Counts, error) {
	var contacts, places int
	err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM contacts WHERE site_id = $1),
		(SELECT count(*) FROM site_places WHERE site_id = $1)`, siteID).Scan(&contacts, &places)
	return Counts{"contacts": contacts, "places": places}, err
}

// OrganizationCounts counts what an organization holds at its own level,
// outside its sites, in the caller's transaction.
func OrganizationCounts(ctx context.Context, tx pgx.Tx, orgID uuid.UUID) (Counts, error) {
	var contacts int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM contacts WHERE organization_id = $1 AND site_id IS NULL`, orgID).Scan(&contacts)
	return Counts{"contacts": contacts, "places": 0}, err
}
