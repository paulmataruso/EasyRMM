//go:build integration

package app_test

import (
	"bytes"
	"encoding/csv"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type contactView struct {
	ID        string  `json:"id"`
	SiteID    *string `json:"siteId"`
	SiteName  string  `json:"siteName"`
	Name      string  `json:"name"`
	Email     string  `json:"email"`
	Priority  string  `json:"priority"`
	Emergency bool    `json:"emergency"`
	CanManage bool    `json:"canManage"`
}

type contactPage struct {
	Items []contactView `json:"items"`
	Next  string        `json:"next"`
}

type placeView struct {
	ID       string  `json:"id"`
	ParentID *string `json:"parentId"`
	Kind     string  `json:"kind"`
	Name     string  `json:"name"`
	Depth    int     `json:"depth"`
}

func contactNames(p contactPage) string {
	var out []string
	for _, c := range p.Items {
		out = append(out, c.Name)
	}
	return strings.Join(out, ",")
}

// TestCustomerRecordAPI drives the customer record through the console API
// (ADR-0066): details, contacts, places, deleting with documentation, the
// Contacts report, and who may do which.
func TestCustomerRecordAPI(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var hq, branch idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "Europe/London"}, &hq)
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "Branch"}, &branch)
	// The address is the customer record's now, not site management's.
	wantStatus(t, admin.do("PUT", "/api/v1/sites/"+hq.ID, map[string]string{"name": "HQ", "address": "1 Example Road"}), http.StatusUnprocessableEntity, "validation_failed")

	// The organization's and the site's details.
	var org struct {
		MainPhone              string         `json:"mainPhone"`
		Website                string         `json:"website"`
		BusinessHours          map[string]any `json:"businessHours"`
		OpenNow                *bool          `json:"openNow"`
		CanManageDocumentation bool           `json:"canManageDocumentation"`
	}
	week := map[string]any{"monday": []map[string]string{{"start": "00:00", "end": "00:00"}}, "tuesday": []any{}}
	admin.expect(http.StatusOK, "PUT", "/api/v1/organizations/"+acme+"/details", map[string]any{
		"mainPhone": "+1 555 0100", "mainEmail": "help@example.com", "website": "example.com", "businessHours": week, "afterHoursNote": ""}, &org)
	if org.MainPhone != "+1 555 0100" || org.Website != "https://example.com" || org.OpenNow == nil || !org.CanManageDocumentation ||
		len(org.BusinessHours["sunday"].([]any)) != 0 {
		t.Fatalf("organization details %+v", org)
	}
	wantStatus(t, admin.do("PUT", "/api/v1/organizations/"+acme+"/details", map[string]any{"mainEmail": "help"}), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("PUT", "/api/v1/organizations/"+acme+"/details", map[string]any{"businessHours": map[string]any{"someday": []any{}}}),
		http.StatusUnprocessableEntity, "validation_failed")
	var site struct {
		AddressLine1          string `json:"addressLine1"`
		CountryCode           string `json:"countryCode"`
		HoursFromOrganization bool   `json:"hoursFromOrganization"`
	}
	admin.expect(http.StatusOK, "PUT", "/api/v1/sites/"+hq.ID+"/details", map[string]any{"addressLine1": "1 Example Road", "countryCode": "gb"}, &site)
	if site.AddressLine1 != "1 Example Road" || site.CountryCode != "GB" || !site.HoursFromOrganization {
		t.Fatalf("site details %+v", site)
	}
	r := admin.do("PUT", "/api/v1/sites/"+hq.ID+"/details", map[string]any{"countryCode": "XX"})
	wantStatus(t, r, http.StatusUnprocessableEntity, "validation_failed")
	if !strings.Contains(string(r.body), `"countryCode"`) {
		t.Fatalf("the field in error: %s", r.body)
	}

	// Contacts.
	var ann, hal contactView
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/contacts",
		map[string]any{"name": "Ann Example", "email": "ann@example.com", "priority": "primary", "emergency": true}, &ann)
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/contacts",
		map[string]any{"siteId": hq.ID, "name": "Hal Desk", "officePhone": "555 0101"}, &hal)
	if ann.SiteID != nil || !ann.Emergency || hal.SiteName != "HQ" || !hal.CanManage {
		t.Fatalf("contacts %+v %+v", ann, hal)
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/contacts", map[string]any{"siteId": branch.ID, "name": "Bea Branch"}, nil)
	wantStatus(t, admin.do("POST", "/api/v1/organizations/"+acme+"/contacts", map[string]any{"name": ""}), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("POST", "/api/v1/organizations/"+acme+"/contacts", map[string]any{"name": "X", "role": "boss"}), http.StatusUnprocessableEntity, "validation_failed")
	var page contactPage
	admin.expect(http.StatusOK, "GET", "/api/v1/organizations/"+acme+"/contacts", nil, &page)
	if contactNames(page) != "Ann Example,Bea Branch,Hal Desk" || page.Next != "" {
		t.Fatalf("contacts %+v", page)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/organizations/"+acme+"/contacts?siteId="+hq.ID, nil, &page)
	if contactNames(page) != "Hal Desk" {
		t.Fatalf("HQ's contacts %+v", page)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/organizations/"+acme+"/contacts?limit=2", nil, &page)
	if contactNames(page) != "Ann Example,Bea Branch" || page.Next == "" {
		t.Fatalf("the first page %+v", page)
	}
	var second contactPage
	admin.expect(http.StatusOK, "GET", "/api/v1/organizations/"+acme+"/contacts?limit=2&after="+url.QueryEscape(page.Next), nil, &second)
	if contactNames(second) != "Hal Desk" || second.Next != "" {
		t.Fatalf("the second page %+v", second)
	}
	for _, q := range []string{"limit=0", "limit=1001", "siteId=nope", "after=nope"} {
		wantStatus(t, admin.do("GET", "/api/v1/organizations/"+acme+"/contacts?"+q, nil), http.StatusUnprocessableEntity, "validation_failed")
	}
	admin.expect(http.StatusOK, "PATCH", "/api/v1/contacts/"+hal.ID, map[string]any{"priority": "primary", "mobilePhone": "555 0102"}, &hal)
	if hal.Priority != "primary" || hal.Name != "Hal Desk" {
		t.Fatalf("patched %+v", hal)
	}
	wantStatus(t, admin.do("PATCH", "/api/v1/contacts/"+hal.ID, map[string]any{"siteId": branch.ID}), http.StatusUnprocessableEntity, "validation_failed")
	for _, c := range []struct{ m, p string }{
		{"GET", "/api/v1/organizations/nope/contacts"}, {"POST", "/api/v1/organizations/nope/contacts"},
		{"PATCH", "/api/v1/contacts/nope"}, {"DELETE", "/api/v1/contacts/nope"},
		{"GET", "/api/v1/sites/nope/places"}, {"POST", "/api/v1/sites/nope/places"},
		{"PATCH", "/api/v1/places/nope"}, {"DELETE", "/api/v1/places/nope"},
		{"PUT", "/api/v1/organizations/nope/details"}, {"PUT", "/api/v1/sites/nope/details"},
	} {
		wantStatus(t, admin.do(c.m, c.p, map[string]string{"name": "x"}), http.StatusNotFound, "not_found")
	}
	// Bodies that are not objects.
	for _, c := range []struct{ m, p string }{
		{"PATCH", "/api/v1/contacts/" + hal.ID}, {"POST", "/api/v1/organizations/" + acme + "/contacts"},
		{"POST", "/api/v1/sites/" + hq.ID + "/places"}, {"PUT", "/api/v1/organizations/" + acme + "/details"},
		{"PUT", "/api/v1/sites/" + hq.ID + "/details"},
	} {
		wantStatus(t, admin.do(c.m, c.p, "x"), http.StatusBadRequest, "")
	}

	// Places.
	var main, floor, room placeView
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+hq.ID+"/places", map[string]any{"kind": "building", "name": "Main"}, &main)
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+hq.ID+"/places", map[string]any{"parentId": main.ID, "kind": "floor", "name": "Ground"}, &floor)
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+hq.ID+"/places", map[string]any{"parentId": floor.ID, "kind": "room", "name": "Server room"}, &room)
	if room.Depth != 3 || *room.ParentID != floor.ID {
		t.Fatalf("a room %+v", room)
	}
	admin.expect(http.StatusOK, "PATCH", "/api/v1/places/"+room.ID, map[string]any{"parentId": nil}, &room)
	if room.Depth != 1 || room.ParentID != nil {
		t.Fatalf("moved to the top %+v", room)
	}
	admin.expect(http.StatusOK, "PATCH", "/api/v1/places/"+room.ID, map[string]any{"parentId": floor.ID}, &room)
	var places struct {
		Items []placeView `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/sites/"+hq.ID+"/places", nil, &places)
	if len(places.Items) != 3 || places.Items[2].Name != "Server room" || places.Items[2].Depth != 3 {
		t.Fatalf("places %+v", places)
	}
	wantStatus(t, admin.do("PATCH", "/api/v1/places/"+room.ID, map[string]any{"parentId": "nope"}), http.StatusBadRequest, "")
	wantStatus(t, admin.do("DELETE", "/api/v1/places/"+main.ID, nil), http.StatusConflict, "place_not_empty")
	wantStatus(t, admin.do("POST", "/api/v1/sites/"+hq.ID+"/places", map[string]any{"kind": "building", "name": "main"}), http.StatusUnprocessableEntity, "validation_failed")

	// Who may do what.
	invite(t, h, admin, "rory@acme.example", []map[string]any{{"role": "read_only", "organizationId": acme}})
	viewer := h.client()
	viewer.signIn("rory@acme.example", "a long and unusual passphrase", "")
	viewer.expect(http.StatusOK, "GET", "/api/v1/organizations/"+acme+"/contacts", nil, &page)
	if len(page.Items) != 3 || page.Items[0].CanManage {
		t.Fatalf("Read-Only's contacts %+v", page)
	}
	for _, c := range []struct {
		m, p string
		body any
	}{
		{"POST", "/api/v1/organizations/" + acme + "/contacts", map[string]any{"name": "X"}},
		{"PATCH", "/api/v1/contacts/" + ann.ID, map[string]any{"name": "X"}},
		{"DELETE", "/api/v1/contacts/" + ann.ID, nil},
		{"POST", "/api/v1/sites/" + hq.ID + "/places", map[string]any{"kind": "room", "name": "X"}},
		{"PATCH", "/api/v1/places/" + room.ID, map[string]any{"name": "X"}},
		{"DELETE", "/api/v1/places/" + room.ID, nil},
		{"PUT", "/api/v1/organizations/" + acme + "/details", map[string]any{}},
		{"PUT", "/api/v1/sites/" + hq.ID + "/details", map[string]any{}},
	} {
		wantStatus(t, viewer.do(c.m, c.p, c.body), http.StatusForbidden, "forbidden")
	}

	invite(t, h, admin, "tess@acme.example", []map[string]any{{"role": "technician", "organizationId": acme, "siteId": hq.ID}})
	tech := h.client()
	tech.signIn("tess@acme.example", "a long and unusual passphrase", "")
	tech.expect(http.StatusOK, "GET", "/api/v1/organizations/"+acme+"/contacts", nil, &page)
	if contactNames(page) != "Hal Desk" {
		t.Fatalf("a site's technician lists %+v", page)
	}
	wantStatus(t, tech.do("POST", "/api/v1/organizations/"+acme+"/contacts", map[string]any{"name": "X"}), http.StatusForbidden, "forbidden")
	wantStatus(t, tech.do("PATCH", "/api/v1/contacts/"+ann.ID, map[string]any{"name": "X"}), http.StatusNotFound, "not_found")
	wantStatus(t, tech.do("GET", "/api/v1/sites/"+branch.ID+"/places", nil), http.StatusNotFound, "not_found")
	tech.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/contacts", map[string]any{"siteId": hq.ID, "name": "Tess's colleague"}, nil)

	var globex idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations", map[string]string{"name": "Globex"}, &globex)
	invite(t, h, admin, "gil@globex.example", []map[string]any{{"role": "org_admin", "organizationId": globex.ID}})
	other := h.client()
	other.signIn("gil@globex.example", "a long and unusual passphrase", "")
	named, place := map[string]any{"name": "X"}, map[string]any{"name": "X", "kind": "room"}
	for _, c := range []struct {
		m, p string
		body any
	}{
		{"GET", "/api/v1/organizations/" + acme + "/contacts", nil}, {"POST", "/api/v1/organizations/" + acme + "/contacts", named},
		{"PATCH", "/api/v1/contacts/" + ann.ID, named}, {"DELETE", "/api/v1/contacts/" + ann.ID, nil},
		{"GET", "/api/v1/sites/" + hq.ID + "/places", nil}, {"POST", "/api/v1/sites/" + hq.ID + "/places", place},
		{"PATCH", "/api/v1/places/" + room.ID, place}, {"DELETE", "/api/v1/places/" + room.ID, nil},
		{"PUT", "/api/v1/organizations/" + acme + "/details", map[string]any{}}, {"PUT", "/api/v1/sites/" + hq.ID + "/details", map[string]any{}},
	} {
		wantStatus(t, other.do(c.m, c.p, c.body), http.StatusNotFound, "not_found")
	}

	// The Contacts report, as CSV.
	r = viewer.do("GET", "/api/v1/reports/contacts/csv?organizationId="+acme, nil)
	wantStatus(t, r, http.StatusOK, "")
	records, err := csv.NewReader(bytes.NewReader(r.body[3:])).ReadAll()
	if err != nil || len(records) != 5 || records[0][2] != "Name" || records[1][2] != "Ann Example" || records[1][8] != "Yes" {
		t.Fatalf("contacts csv %q %v", records, err)
	}

	// Deleting a site that holds documentation needs its counts.
	r = admin.do("DELETE", "/api/v1/sites/"+hq.ID, nil)
	wantStatus(t, r, http.StatusConflict, "documentation_exists")
	var refusal struct {
		Error struct {
			Counts map[string]int `json:"counts"`
		} `json:"error"`
	}
	r.decode(t, &refusal)
	if refusal.Error.Counts["contacts"] != 2 || refusal.Error.Counts["places"] != 3 {
		t.Fatalf("counts %s", r.body)
	}
	wantStatus(t, admin.do("DELETE", "/api/v1/sites/"+hq.ID+"?contacts=two&places=3", nil), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("DELETE", "/api/v1/sites/"+hq.ID+"?contacts=1&places=3", nil), http.StatusConflict, "documentation_changed")
	admin.expect(http.StatusNoContent, "DELETE", "/api/v1/sites/"+hq.ID+"?contacts=2&places=3", nil, nil)
	admin.expect(http.StatusNoContent, "DELETE", "/api/v1/sites/"+branch.ID+"?contacts=1", nil, nil)
	wantStatus(t, admin.do("DELETE", "/api/v1/organizations/"+acme, nil), http.StatusConflict, "documentation_exists")

	var audit struct {
		Items []struct {
			Action string `json:"action"`
		} `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/audit?action=contact", nil, &audit)
	if len(audit.Items) != 5 || audit.Items[len(audit.Items)-1].Action != "contact.create" {
		t.Fatalf("contact audit %+v", audit.Items)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/audit?action=site_place", nil, &audit)
	if len(audit.Items) != 5 {
		t.Fatalf("place audit %+v", audit.Items)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/audit?action=site", nil, &audit)
	for _, a := range audit.Items {
		if strings.HasPrefix(a.Action, "site_place") {
			t.Fatalf("the site filter took a place's entry: %+v", audit.Items)
		}
	}
}
