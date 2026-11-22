//go:build integration

package tenancy_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/docs"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/tenancy"
)

// always is open around the clock, every day.
func always() *docs.Hours {
	day := func() []docs.Interval { return []docs.Interval{{Start: "00:00", End: "00:00"}} }
	return &docs.Hours{Monday: day(), Tuesday: day(), Wednesday: day(), Thursday: day(), Friday: day(), Saturday: day(), Sunday: day()}
}

// notNow is open one minute three days from now in loc: closed now.
func notNow(t *testing.T, tz string) *docs.Hours {
	t.Helper()
	loc, err := time.LoadLocation(tz)
	if err != nil {
		t.Fatal(err)
	}
	h := &docs.Hours{}
	day := map[time.Weekday]*[]docs.Interval{time.Monday: &h.Monday, time.Tuesday: &h.Tuesday, time.Wednesday: &h.Wednesday,
		time.Thursday: &h.Thursday, time.Friday: &h.Friday, time.Saturday: &h.Saturday, time.Sunday: &h.Sunday}
	*day[time.Now().In(loc).AddDate(0, 0, 3).Weekday()] = []docs.Interval{{Start: "12:00", End: "12:01"}}
	return h
}

func (e *env) details(prefix string) []audit.Entry {
	entries, err := e.audit.List(context.Background(), database.System, audit.Query{ActionPrefix: prefix})
	if err != nil {
		panic(err)
	}
	return entries
}

func fieldsOf(en audit.Entry) string {
	b, _ := json.Marshal(en.Details["fields"])
	return string(b)
}

func TestCustomerDetails(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	w := e.world(t)
	if w.orgA.BusinessHours != nil || w.orgA.OpenNow != nil || !w.orgA.CanManageDocumentation || w.orgA.MainPhone != "" {
		t.Fatalf("a new organization's details %+v", w.orgA)
	}

	o, err := e.svc.UpdateOrganizationDetails(ctx, e.sys, w.orgA.ID, tenancy.OrganizationDetails{
		MainPhone: " +1 555 0100 ", MainEmail: "help@example.com", Website: "www.example.com",
		BusinessHours: always(), AfterHoursNote: "Call the on-call line.\r\n"})
	if err != nil {
		t.Fatal(err)
	}
	if o.MainPhone != "+1 555 0100" || o.Website != "https://www.example.com" || o.AfterHoursNote != "Call the on-call line." ||
		o.BusinessHours == nil || o.OpenNow == nil || !*o.OpenNow || o.Name != "Acme" {
		t.Fatalf("details %+v", o)
	}
	// The same again changes nothing and is not recorded.
	if _, err := e.svc.UpdateOrganizationDetails(ctx, e.sys, w.orgA.ID, tenancy.OrganizationDetails{
		MainPhone: "+1 555 0100", MainEmail: "help@example.com", Website: "https://www.example.com",
		BusinessHours: always(), AfterHoursNote: "Call the on-call line."}); err != nil {
		t.Fatal(err)
	}
	recorded := e.details("organization.details_update")
	if len(recorded) != 1 || fieldsOf(recorded[0]) != `["mainPhone","mainEmail","website","businessHours","afterHoursNote"]` {
		t.Fatalf("recorded %+v", recorded)
	}
	for name, c := range map[string]struct {
		in    tenancy.OrganizationDetails
		field string
	}{
		"phone":   {tenancy.OrganizationDetails{MainPhone: "front desk"}, "mainPhone"},
		"email":   {tenancy.OrganizationDetails{MainEmail: "help at example.com"}, "mainEmail"},
		"website": {tenancy.OrganizationDetails{Website: "ftp://example.com"}, "website"},
		"note":    {tenancy.OrganizationDetails{AfterHoursNote: strings.Repeat("n", 2001)}, "afterHoursNote"},
		"hours": {tenancy.OrganizationDetails{BusinessHours: &docs.Hours{Monday: []docs.Interval{{Start: "09:00", End: "17:00"},
			{Start: "16:00", End: "18:00"}}}}, "businessHours"},
	} {
		_, err := e.svc.UpdateOrganizationDetails(ctx, e.sys, w.orgA.ID, c.in)
		wantField(t, err, c.field, name)
	}
	if _, err := e.svc.UpdateOrganizationDetails(ctx, e.sys, uuid.New(), tenancy.OrganizationDetails{}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("a missing organization: %v", err)
	}

	// A site without hours of its own reads its organization's, in its own
	// time zone.
	s, err := e.svc.GetSite(ctx, e.sys, w.siteA.ID)
	if err != nil || !s.HoursFromOrganization || s.OpenNow == nil || !*s.OpenNow || s.BusinessHours != nil || !s.CanManageDocumentation {
		t.Fatalf("a site on its organization's hours %v %+v", err, s)
	}
	s, err = e.svc.UpdateSiteDetails(ctx, e.sys, w.siteA.ID, tenancy.SiteDetails{
		Address: "Unit 4\r\nExample Trading Estate", AddressLine1: "1 Example Road", City: "Exampleton", PostalCode: "EX1 1AA",
		CountryCode: " gb ", BusinessHours: notNow(t, "Europe/London"), AfterHoursNote: "Ring the bell."})
	if err != nil {
		t.Fatal(err)
	}
	if s.Address != "Unit 4\nExample Trading Estate" || s.CountryCode != "GB" || s.City != "Exampleton" || s.HoursFromOrganization ||
		s.OpenNow == nil || *s.OpenNow || s.Name != "HQ" || s.Timezone != "Europe/London" {
		t.Fatalf("site details %+v", s)
	}
	if list, err := e.svc.ListSites(ctx, e.sys, w.orgA.ID, ""); err != nil || list[0].PostalCode != "EX1 1AA" || list[0].OpenNow == nil {
		t.Fatalf("the site list %v %+v", err, list)
	}
	// Keeping no hours of its own goes back to the organization's.
	s, err = e.svc.UpdateSiteDetails(ctx, e.sys, w.siteA.ID, tenancy.SiteDetails{AddressLine1: "1 Example Road", CountryCode: "GB",
		BusinessHours: &docs.Hours{}})
	if err != nil || s.BusinessHours != nil || !s.HoursFromOrganization || s.Address != "" {
		t.Fatalf("without hours %v %+v", err, s)
	}
	recorded = e.details("site.details_update")
	if len(recorded) != 2 || fieldsOf(recorded[0]) != `["address","city","postalCode","businessHours","afterHoursNote"]` {
		t.Fatalf("recorded %d: %s", len(recorded), fieldsOf(recorded[0]))
	}
	if recorded[0].SiteID == nil || *recorded[0].SiteID != w.siteA.ID {
		t.Fatalf("not filed under the site: %+v", recorded[0])
	}
	// Neither record holds a value.
	for _, en := range append(e.details("organization.details_update"), recorded...) {
		b, _ := json.Marshal(en.Details)
		for _, leak := range []string{"555", "example.com", "Example", "EX1", "bell", "on-call", "12:00"} {
			if strings.Contains(string(b), leak) {
				t.Errorf("%s holds %q: %s", en.Action, leak, b)
			}
		}
	}
	for name, c := range map[string]struct {
		in    tenancy.SiteDetails
		field string
	}{
		"address":  {tenancy.SiteDetails{Address: strings.Repeat("a", 1001)}, "address"},
		"line 1":   {tenancy.SiteDetails{AddressLine1: strings.Repeat("a", 201)}, "addressLine1"},
		"line 2":   {tenancy.SiteDetails{AddressLine2: strings.Repeat("a", 201)}, "addressLine2"},
		"city":     {tenancy.SiteDetails{City: strings.Repeat("a", 101)}, "city"},
		"region":   {tenancy.SiteDetails{Region: strings.Repeat("a", 101)}, "region"},
		"postcode": {tenancy.SiteDetails{PostalCode: strings.Repeat("1", 21)}, "postalCode"},
		"country":  {tenancy.SiteDetails{CountryCode: "UK"}, "countryCode"},
		"note":     {tenancy.SiteDetails{AfterHoursNote: strings.Repeat("n", 2001)}, "afterHoursNote"},
		"hours":    {tenancy.SiteDetails{BusinessHours: &docs.Hours{Friday: []docs.Interval{{Start: "9:00", End: "17:00"}}}}, "businessHours"},
	} {
		_, err := e.svc.UpdateSiteDetails(ctx, e.sys, w.siteA.ID, c.in)
		wantField(t, err, c.field, name)
	}
	if _, err := e.svc.UpdateSiteDetails(ctx, e.sys, uuid.New(), tenancy.SiteDetails{}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("a missing site: %v", err)
	}
	// Site management no longer writes the address.
	if s, err := e.svc.UpdateSite(ctx, e.sys, w.siteA.ID, tenancy.SiteInput{Name: "HQ", Timezone: "Europe/London"}); err != nil || s.AddressLine1 != "1 Example Road" {
		t.Fatalf("renaming kept the address? %v %+v", err, s)
	}
}

func TestCustomerDetailsAccess(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	w := e.world(t)
	if _, err := e.svc.UpdateOrganizationDetails(ctx, e.sys, w.orgA.ID, tenancy.OrganizationDetails{MainPhone: "555 0100", BusinessHours: always()}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.UpdateSiteDetails(ctx, e.sys, w.siteA.ID, tenancy.SiteDetails{City: "Exampleton"}); err != nil {
		t.Fatal(err)
	}

	// A site's technician reads the organization's details and changes its
	// site's, not the organization's.
	tech := caller(t, rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: w.orgA.ID, SiteID: w.siteA.ID})
	o, err := e.svc.GetOrganization(ctx, tech, w.orgA.ID)
	if err != nil || o.MainPhone != "555 0100" || o.CanManageDocumentation || o.OpenNow == nil {
		t.Fatalf("a site's technician reads %v %+v", err, o)
	}
	if _, err := e.svc.UpdateOrganizationDetails(ctx, tech, w.orgA.ID, tenancy.OrganizationDetails{}); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("a site's technician changes the organization's: %v", err)
	}
	s, err := e.svc.GetSite(ctx, tech, w.siteA.ID)
	if err != nil || s.City != "Exampleton" || !s.CanManageDocumentation || s.CanManage {
		t.Fatalf("a site's technician reads the site %v %+v", err, s)
	}
	if _, err := e.svc.UpdateSiteDetails(ctx, tech, w.siteA.ID, tenancy.SiteDetails{City: "Example City"}); err != nil {
		t.Fatalf("a site's technician changes the site's: %v", err)
	}

	// Read-Only reads them and changes neither.
	ro := caller(t, rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: w.orgA.ID})
	if o, err := e.svc.GetOrganization(ctx, ro, w.orgA.ID); err != nil || o.MainPhone == "" || o.CanManageDocumentation {
		t.Fatalf("Read-Only reads %v %+v", err, o)
	}
	if _, err := e.svc.UpdateOrganizationDetails(ctx, ro, w.orgA.ID, tenancy.OrganizationDetails{}); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("Read-Only changes the organization's: %v", err)
	}
	if _, err := e.svc.UpdateSiteDetails(ctx, ro, w.siteA.ID, tenancy.SiteDetails{}); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("Read-Only changes the site's: %v", err)
	}

	// Another organization's administrator finds neither.
	other := caller(t, rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: w.orgB.ID})
	if _, err := e.svc.UpdateOrganizationDetails(ctx, other, w.orgA.ID, tenancy.OrganizationDetails{}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("another organization's administrator: %v", err)
	}
	if _, err := e.svc.UpdateSiteDetails(ctx, other, w.siteA.ID, tenancy.SiteDetails{}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("another organization's administrator, a site: %v", err)
	}

	// Without doc.view where they are, a scope that reaches the rows shows
	// the organization and the site without their details.
	blind := caller(t, rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: w.orgB.ID})
	blind.Scope = database.Scope{Orgs: []uuid.UUID{w.orgA.ID, w.orgB.ID}}
	orgs, err := e.svc.ListOrganizations(ctx, blind, "")
	if err != nil || len(orgs) != 2 {
		t.Fatal(err)
	}
	i := slices.IndexFunc(orgs, func(o tenancy.Organization) bool { return o.ID == w.orgA.ID })
	if o := orgs[i]; o.MainPhone != "" || o.BusinessHours != nil || o.OpenNow != nil || o.CanManageDocumentation {
		t.Fatalf("without doc.view, the organization %+v", o)
	}
	if s, err := e.svc.GetSite(ctx, blind, w.siteA.ID); err != nil || s.City != "" || s.OpenNow != nil || s.HoursFromOrganization || s.CanManageDocumentation {
		t.Fatalf("without doc.view, the site %v %+v", err, s)
	}
	if _, err := e.svc.UpdateSiteDetails(ctx, blind, w.siteA.ID, tenancy.SiteDetails{}); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("without doc.manage, a change: %v", err)
	}
}

// TestDeletingDocumentation: deleting a site or an organization that holds
// documentation needs the counts confirmed, and records them.
func TestDeletingDocumentation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	w := e.world(t)
	ds := docs.New(e.db, e.audit)
	add := func(org uuid.UUID, site *uuid.UUID, name string) {
		if _, err := ds.CreateContact(ctx, e.sys, org, docs.ContactInput{SiteID: site, Name: name}); err != nil {
			t.Fatal(err)
		}
	}
	add(w.orgA.ID, &w.siteA.ID, "Hal Desk")
	add(w.orgA.ID, &w.siteA.ID, "Hal Two")
	add(w.orgA.ID, nil, "Ann Example")
	if _, err := ds.CreatePlace(ctx, e.sys, w.siteA.ID, docs.PlaceInput{Kind: "building", Name: "Main"}); err != nil {
		t.Fatal(err)
	}

	err := e.svc.DeleteSite(ctx, e.sys, w.siteA.ID, nil)
	ae := wantKind(t, err, apperr.KindConflict, "a site with documentation")
	if ae.Code != "documentation_exists" || ae.Counts["contacts"] != 2 || ae.Counts["places"] != 1 || !strings.Contains(ae.Message, "2 contacts and 1 place") {
		t.Fatalf("refusal %+v", ae)
	}
	ae = wantKind(t, e.svc.DeleteSite(ctx, e.sys, w.siteA.ID, docs.Counts{"contacts": 1, "places": 1}), apperr.KindConflict, "stale counts")
	if ae.Code != "documentation_changed" || ae.Counts["contacts"] != 2 {
		t.Fatalf("stale counts %+v", ae)
	}

	// Devices come first: confirming the documentation would not help.
	add(w.orgB.ID, &w.siteB.ID, "Gus Plant")
	if err := e.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO devices (organization_id, site_id, name, hostname, platform, last_seen_at)
			VALUES ($1, $2, 'D-1', 'd-1', 'other', now())`, w.orgB.ID, w.siteB.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if ae := wantKind(t, e.svc.DeleteSite(ctx, e.sys, w.siteB.ID, nil), apperr.KindConflict, "a site with devices"); ae.Code != "site_not_empty" {
		t.Fatalf("a site with devices and documentation: %+v", ae)
	}

	if err := e.svc.DeleteSite(ctx, e.sys, w.siteA.ID, docs.Counts{"contacts": 2, "places": 1}); err != nil {
		t.Fatal(err)
	}
	deleted := e.details("site.delete")
	if b, _ := json.Marshal(deleted[0].Details["documentation"]); string(b) != `{"contacts":2,"places":1}` {
		t.Fatalf("the deletion's record %+v", deleted[0].Details)
	}

	// The organization's own contacts, once its sites are gone.
	err = e.svc.DeleteOrganization(ctx, e.sys, w.orgA.ID, nil)
	if ae := wantKind(t, err, apperr.KindConflict, "an organization with contacts"); ae.Code != "documentation_exists" || ae.Counts["contacts"] != 1 {
		t.Fatalf("refusal %+v", ae)
	}
	if err := e.svc.DeleteOrganization(ctx, e.sys, w.orgA.ID, docs.Counts{"contacts": 1}); err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(e.details("organization.delete")[0].Details["documentation"]); string(b) != `{"contacts":1,"places":0}` {
		t.Fatalf("the organization's deletion record %s", b)
	}
	err = e.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM contacts WHERE organization_id = $1) + (SELECT count(*) FROM site_places)`,
			w.orgA.ID).Scan(&n); err != nil || n != 0 {
			t.Errorf("%d rows outlived their organization: %v", n, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
