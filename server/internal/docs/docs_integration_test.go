//go:build integration

package docs_test

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

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/docs"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/tenancy"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

// env is two customers: Acme with two sites, Globex with one.
type env struct {
	t                *testing.T
	ctx              context.Context
	db               *database.DB
	svc              *docs.Service
	audit            *audit.Logger
	sys              access.Caller
	acme, hq, branch uuid.UUID
	globex, plant    uuid.UUID
	// superDSN connects as the superuser, to watch other sessions wait.
	superDSN string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	inst := testdb.New(t)
	al := audit.New(inst.DB, nil)
	e := &env{t: t, ctx: context.Background(), db: inst.DB, svc: docs.New(inst.DB, al), audit: al, sys: access.System("test"),
		superDSN: inst.SuperDSN}
	ten := tenancy.New(inst.DB, al)
	org := func(name string) uuid.UUID {
		o, err := ten.CreateOrganization(e.ctx, e.sys, tenancy.OrganizationInput{Name: name})
		if err != nil {
			t.Fatal(err)
		}
		return o.ID
	}
	site := func(org uuid.UUID, name string) uuid.UUID {
		s, err := ten.CreateSite(e.ctx, e.sys, org, tenancy.SiteInput{Name: name})
		if err != nil {
			t.Fatal(err)
		}
		return s.ID
	}
	e.acme, e.globex = org("Acme"), org("Globex")
	e.hq, e.branch, e.plant = site(e.acme, "HQ"), site(e.acme, "Branch"), site(e.globex, "Plant")
	return e
}

func (e *env) caller(as ...rbac.Assignment) access.Caller {
	e.t.Helper()
	uid := uuid.New()
	p, err := rbac.NewPrincipal(uid, as)
	if err != nil {
		e.t.Fatal(err)
	}
	return access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: uid, Label: "user@example.com"})
}

func (e *env) contact(c access.Caller, org uuid.UUID, in docs.ContactInput) *docs.Contact {
	e.t.Helper()
	x, err := e.svc.CreateContact(e.ctx, c, org, in)
	if err != nil {
		e.t.Fatalf("contact %q: %v", in.Name, err)
	}
	return x
}

func (e *env) place(c access.Caller, site uuid.UUID, parent *uuid.UUID, kind, name string) *docs.Place {
	e.t.Helper()
	p, err := e.svc.CreatePlace(e.ctx, c, site, docs.PlaceInput{ParentID: parent, Kind: kind, Name: name})
	if err != nil {
		e.t.Fatalf("place %q: %v", name, err)
	}
	return p
}

func (e *env) count(sql string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.db.ReadTx(e.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(e.ctx, sql, args...).Scan(&n) }); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func (e *env) entries(prefix string) []audit.Entry {
	e.t.Helper()
	out, err := e.audit.List(e.ctx, database.System, audit.Query{ActionPrefix: prefix, Limit: 500})
	if err != nil {
		e.t.Fatal(err)
	}
	return out
}

func wantCode(t *testing.T, err error, kind apperr.Kind, code, what string) {
	t.Helper()
	ae, ok := apperr.As(err)
	if !ok || ae.Kind != kind || (code != "" && ae.Code != code) {
		t.Fatalf("%s: got %v, want kind %d %s", what, err, kind, code)
	}
}

func wantField(t *testing.T, err error, field, what string) {
	t.Helper()
	wantCode(t, err, apperr.KindInvalid, "", what)
	if ae, _ := apperr.As(err); ae.Fields[field] == "" {
		t.Fatalf("%s: fields %v, want %q", what, ae.Fields, field)
	}
}

func names(cs []docs.Contact) []string {
	out := []string{}
	for _, c := range cs {
		out = append(out, c.Name)
	}
	return out
}

func ptr[T any](v T) *T { return &v }

// raced runs write while another transaction makes change and holds it
// uncommitted: write reads what was there before, then waits on a lock
// change holds, and goes on once change commits. change takes whatever
// locks it means write to wait on.
func (e *env) raced(change func(tx pgx.Tx) error, write func() error) error {
	e.t.Helper()
	watch, err := pgx.Connect(e.ctx, e.superDSN)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = watch.Close(context.Background()) }()
	done := make(chan error, 1)
	var early error
	err = e.db.InTx(e.ctx, database.System, func(tx pgx.Tx) error {
		if err := change(tx); err != nil {
			return err
		}
		go func() { done <- write() }()
		for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			select {
			case early = <-done:
				return errors.New("the write did not wait")
			default:
			}
			var waiting bool
			if err := watch.QueryRow(e.ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
				WHERE datname = current_database() AND wait_event_type = 'Lock')`).Scan(&waiting); err != nil {
				return err
			}
			if waiting {
				return nil
			}
		}
		return errors.New("the write never waited")
	})
	if err != nil {
		e.t.Fatalf("%v (the write: %v)", err, early)
	}
	return <-done
}

func TestContacts(t *testing.T) {
	e := newEnv(t)

	ann := e.contact(e.sys, e.acme, docs.ContactInput{Name: " Ann\tExample ", JobTitle: "Director", Email: "ann@example.com",
		OfficePhone: "+1 555 0100", Note: "Line one\r\nLine two", Priority: "primary", Emergency: true})
	if ann.Name != "Ann Example" || ann.Note != "Line one\nLine two" || ann.SiteID != nil || ann.SiteName != "" || !ann.CanManage ||
		ann.Priority != "primary" || !ann.Emergency {
		t.Fatalf("created %+v", ann)
	}
	bob := e.contact(e.sys, e.acme, docs.ContactInput{Name: "Bob Example"})
	if bob.Priority != "none" {
		t.Fatalf("default priority %q", bob.Priority)
	}
	hal := e.contact(e.sys, e.acme, docs.ContactInput{SiteID: &e.hq, Name: "Hal Desk", Priority: "primary"})
	if hal.SiteName != "HQ" || *hal.SiteID != e.hq {
		t.Fatalf("a site's contact %+v", hal)
	}
	e.contact(e.sys, e.acme, docs.ContactInput{SiteID: &e.branch, Name: "Bea Branch", Priority: "secondary"})
	e.contact(e.sys, e.globex, docs.ContactInput{SiteID: &e.plant, Name: "Gus Plant"})

	for name, c := range map[string]struct {
		in    docs.ContactInput
		field string
	}{
		"no name":      {docs.ContactInput{Name: " \t "}, "name"},
		"long name":    {docs.ContactInput{Name: strings.Repeat("n", 201)}, "name"},
		"long title":   {docs.ContactInput{Name: "X", JobTitle: strings.Repeat("t", 201)}, "jobTitle"},
		"two emails":   {docs.ContactInput{Name: "X", Email: "a@example.com, b@example.com"}, "email"},
		"phone":        {docs.ContactInput{Name: "X", OfficePhone: "reception"}, "officePhone"},
		"mobile":       {docs.ContactInput{Name: "X", MobilePhone: strings.Repeat("5", 51)}, "mobilePhone"},
		"long note":    {docs.ContactInput{Name: "X", Note: strings.Repeat("é", 2001)}, "note"},
		"bad priority": {docs.ContactInput{Name: "X", Priority: "urgent"}, "priority"},
	} {
		_, err := e.svc.CreateContact(e.ctx, e.sys, e.acme, c.in)
		wantField(t, err, c.field, name)
	}
	if _, err := e.svc.CreateContact(e.ctx, e.sys, uuid.New(), docs.ContactInput{Name: "X"}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("a contact of no organization: %v", err)
	}
	if _, err := e.svc.CreateContact(e.ctx, e.sys, e.acme, docs.ContactInput{SiteID: &e.plant, Name: "X"}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("a contact at another organization's site: %v", err)
	}

	// One primary at the organization's level and one per site: a new
	// primary makes the one before it secondary, and says so in the audit
	// log by its ID.
	cid := e.contact(e.sys, e.acme, docs.ContactInput{Name: "Cid Example", Priority: "primary"})
	list, _, err := e.svc.ListContacts(e.ctx, e.sys, e.acme, docs.ContactQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if got := names(list); !slices.Equal(got, []string{"Cid Example", "Ann Example", "Bob Example", "Bea Branch", "Hal Desk"}) {
		t.Fatalf("order %v", got)
	}
	if list[1].Priority != "secondary" || list[4].Priority != "primary" {
		t.Fatalf("priorities after a new primary: %+v", list)
	}
	created := e.entries("contact.create")
	if created[0].TargetID != cid.ID.String() || created[0].Details["previousPrimaryId"] != ann.ID.String() {
		t.Fatalf("the new primary's audit entry %+v", created[0])
	}
	// The contact made secondary has a record of its own, written first.
	demotedAnn := e.entries("contact.update")[0]
	if d, _ := json.Marshal(demotedAnn.Details); demotedAnn.TargetID != ann.ID.String() || demotedAnn.ID > created[0].ID ||
		demotedAnn.OrganizationID == nil || *demotedAnn.OrganizationID != e.acme || demotedAnn.SiteID != nil ||
		string(d) != `{"emergency":true,"fields":["priority"],"primaryId":"`+cid.ID.String()+`","priority":"secondary"}` {
		t.Fatalf("the demoted contact's audit entry %+v %s", demotedAnn, d)
	}

	// Changes: what a patch names, cleaned; making a contact primary demotes
	// the other; a change that changes nothing is not recorded.
	upd, err := e.svc.UpdateContact(e.ctx, e.sys, ann.ID, docs.ContactPatch{Priority: ptr("primary"), MobilePhone: ptr(" 555 0199 "), Emergency: ptr(false)})
	if err != nil || upd.Priority != "primary" || upd.MobilePhone != "555 0199" || upd.Emergency || upd.JobTitle != "Director" {
		t.Fatalf("update %v %+v", err, upd)
	}
	if again, _, _ := e.svc.ListContacts(e.ctx, e.sys, e.acme, docs.ContactQuery{}); again[0].ID != ann.ID || again[1].Priority != "secondary" {
		t.Fatalf("after making Ann primary again: %+v", again[:2])
	}
	before := len(e.entries("contact.update"))
	if same, err := e.svc.UpdateContact(e.ctx, e.sys, ann.ID, docs.ContactPatch{Name: ptr("Ann Example "), Priority: ptr("primary")}); err != nil || same.ID != ann.ID {
		t.Fatalf("an update that changes nothing: %v", err)
	}
	updates := e.entries("contact.update")
	if len(updates) != before {
		t.Fatalf("an update that changed nothing was recorded")
	}
	if f, _ := json.Marshal(updates[0].Details["fields"]); string(f) != `["mobilePhone","priority","emergency"]` {
		t.Fatalf("changed fields %s", f)
	}
	_, err = e.svc.UpdateContact(e.ctx, e.sys, ann.ID, docs.ContactPatch{Email: ptr("not an address")})
	wantField(t, err, "email", "update with a bad email")
	if _, err := e.svc.UpdateContact(e.ctx, e.sys, uuid.New(), docs.ContactPatch{Name: ptr("X")}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("update a missing contact: %v", err)
	}

	// One site's contacts, and pages.
	if hq, _, err := e.svc.ListContacts(e.ctx, e.sys, e.acme, docs.ContactQuery{SiteID: e.hq}); err != nil || !slices.Equal(names(hq), []string{"Hal Desk"}) {
		t.Fatalf("HQ's contacts %v %v", err, names(hq))
	}
	if _, _, err := e.svc.ListContacts(e.ctx, e.sys, e.acme, docs.ContactQuery{SiteID: e.plant}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("another organization's site: %v", err)
	}
	var paged []string
	after := ""
	for range 10 {
		page, next, err := e.svc.ListContacts(e.ctx, e.sys, e.acme, docs.ContactQuery{After: after, Limit: 2})
		if err != nil {
			t.Fatal(err)
		}
		paged = append(paged, names(page)...)
		if after = next; after == "" {
			break
		}
	}
	all, _, _ := e.svc.ListContacts(e.ctx, e.sys, e.acme, docs.ContactQuery{})
	if !slices.Equal(paged, names(all)) || len(paged) != 5 {
		t.Fatalf("pages %v, whole %v", paged, names(all))
	}

	// The overview's key contacts: the primary ones and the emergency ones.
	if _, err := e.svc.UpdateContact(e.ctx, e.sys, bob.ID, docs.ContactPatch{Emergency: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	key, _, err := e.svc.ListContacts(e.ctx, e.sys, e.acme, docs.ContactQuery{Key: true})
	if got := names(key); err != nil || !slices.Equal(got, []string{"Ann Example", "Bob Example", "Hal Desk"}) {
		t.Fatalf("key contacts %v %v", got, err)
	}
	if _, err := e.svc.UpdateContact(e.ctx, e.sys, bob.ID, docs.ContactPatch{Emergency: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	_, _, err = e.svc.ListContacts(e.ctx, e.sys, e.acme, docs.ContactQuery{After: "not-a-cursor"})
	wantField(t, err, "after", "a bad cursor")

	// Deleting.
	if err := e.svc.DeleteContact(e.ctx, e.sys, bob.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeleteContact(e.ctx, e.sys, bob.ID); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("delete again: %v", err)
	}

	// The audit log holds identifiers, field names and choices: never a
	// contact's name, address, number or note.
	for _, en := range e.entries("contact") {
		b, _ := json.Marshal(en.Details)
		for _, leak := range []string{"Example", "example.com", "555", "Director", "Line"} {
			if strings.Contains(string(b), leak) {
				t.Errorf("%s holds %q: %s", en.Action, leak, b)
			}
		}
		if en.OrganizationID == nil || *en.OrganizationID != e.acme && *en.OrganizationID != e.globex {
			t.Errorf("%s is not filed under its organization", en.Action)
		}
	}
	for _, en := range e.entries("contact.create") {
		if en.TargetID == hal.ID.String() && (en.SiteID == nil || *en.SiteID != e.hq) {
			t.Errorf("a site's contact is not filed under its site: %+v", en)
		}
	}

	// At most 1,000 at a level.
	if err := e.db.InTx(e.ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(e.ctx, `INSERT INTO contacts (organization_id, site_id, name) SELECT $1, $2, 'Bulk ' || n FROM generate_series(1, 999) n`, e.globex, e.plant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.CreateContact(e.ctx, e.sys, e.globex, docs.ContactInput{SiteID: &e.plant, Name: "One more"})
	wantCode(t, err, apperr.KindConflict, "too_many_contacts", "past the limit")
	e.contact(e.sys, e.globex, docs.ContactInput{Name: "At the organization"})
}

// TestContactAccess checks each way to the contacts of another
// organization, another site, and a level without the permission.
func TestContactAccess(t *testing.T) {
	e := newEnv(t)
	own := e.contact(e.sys, e.acme, docs.ContactInput{Name: "Ann Example"})
	atHQ := e.contact(e.sys, e.acme, docs.ContactInput{SiteID: &e.hq, Name: "Hal Desk"})
	atBranch := e.contact(e.sys, e.acme, docs.ContactInput{SiteID: &e.branch, Name: "Bea Branch"})

	// Another organization's administrator sees none of it.
	other := e.caller(rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: e.globex})
	if _, _, err := e.svc.ListContacts(e.ctx, other, e.acme, docs.ContactQuery{}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("another organization's administrator lists: %v", err)
	}
	if _, err := e.svc.CreateContact(e.ctx, other, e.acme, docs.ContactInput{Name: "X"}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("another organization's administrator adds: %v", err)
	}
	if _, err := e.svc.CreateContact(e.ctx, other, e.globex, docs.ContactInput{SiteID: &e.hq, Name: "X"}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("a contact of Globex at Acme's site: %v", err)
	}
	for _, x := range []*docs.Contact{own, atHQ} {
		if _, err := e.svc.UpdateContact(e.ctx, other, x.ID, docs.ContactPatch{Name: ptr("X")}); !errors.Is(err, apperr.ErrNotFound) {
			t.Fatalf("another organization's administrator changes: %v", err)
		}
		if err := e.svc.DeleteContact(e.ctx, other, x.ID); !errors.Is(err, apperr.ErrNotFound) {
			t.Fatalf("another organization's administrator deletes: %v", err)
		}
	}

	// A site's technician reads and changes the site's contacts, not the
	// organization's own nor another site's.
	tech := e.caller(rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: e.acme, SiteID: e.hq})
	list, _, err := e.svc.ListContacts(e.ctx, tech, e.acme, docs.ContactQuery{})
	if err != nil || !slices.Equal(names(list), []string{"Hal Desk"}) || !list[0].CanManage {
		t.Fatalf("a site's technician lists %v %+v", err, list)
	}
	if _, _, err := e.svc.ListContacts(e.ctx, tech, e.acme, docs.ContactQuery{SiteID: e.branch}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("a site's technician lists another site: %v", err)
	}
	if _, err := e.svc.CreateContact(e.ctx, tech, e.acme, docs.ContactInput{Name: "X"}); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("a site's technician adds to the organization: %v", err)
	}
	if _, err := e.svc.CreateContact(e.ctx, tech, e.acme, docs.ContactInput{SiteID: &e.branch, Name: "X"}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("a site's technician adds to another site: %v", err)
	}
	for _, x := range []*docs.Contact{own, atBranch} {
		if _, err := e.svc.UpdateContact(e.ctx, tech, x.ID, docs.ContactPatch{Name: ptr("X")}); !errors.Is(err, apperr.ErrNotFound) {
			t.Fatalf("a site's technician changes %s: %v", x.Name, err)
		}
		if err := e.svc.DeleteContact(e.ctx, tech, x.ID); !errors.Is(err, apperr.ErrNotFound) {
			t.Fatalf("a site's technician deletes %s: %v", x.Name, err)
		}
	}
	mine := e.contact(tech, e.acme, docs.ContactInput{SiteID: &e.hq, Name: "New Desk", Priority: "primary"})
	if _, err := e.svc.UpdateContact(e.ctx, tech, mine.ID, docs.ContactPatch{JobTitle: ptr("Help desk")}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeleteContact(e.ctx, tech, mine.ID); err != nil {
		t.Fatal(err)
	}

	// Read-Only reads and changes nothing.
	ro := e.caller(rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: e.acme})
	if list, _, err := e.svc.ListContacts(e.ctx, ro, e.acme, docs.ContactQuery{}); err != nil || len(list) != 3 || list[0].CanManage {
		t.Fatalf("Read-Only lists %v %+v", err, list)
	}
	if _, err := e.svc.CreateContact(e.ctx, ro, e.acme, docs.ContactInput{SiteID: &e.hq, Name: "X"}); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("Read-Only adds: %v", err)
	}
	if _, err := e.svc.UpdateContact(e.ctx, ro, atHQ.ID, docs.ContactPatch{Name: ptr("X")}); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("Read-Only changes: %v", err)
	}
	if err := e.svc.DeleteContact(e.ctx, ro, own.ID); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("Read-Only deletes: %v", err)
	}

	// A role without doc.view where the rows are reads none of them, even
	// with a data scope that reaches them.
	blind := e.caller(rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: e.globex})
	blind.Scope = database.Scope{Orgs: []uuid.UUID{e.acme, e.globex}}
	if _, _, err := e.svc.ListContacts(e.ctx, blind, e.acme, docs.ContactQuery{}); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("without doc.view, the list: %v", err)
	}
	if _, _, err := e.svc.ListContacts(e.ctx, blind, e.acme, docs.ContactQuery{SiteID: e.hq}); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("without doc.view, a site's list: %v", err)
	}
	if _, err := e.svc.UpdateContact(e.ctx, blind, atHQ.ID, docs.ContactPatch{Name: ptr("X")}); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("without doc.view, a change: %v", err)
	}
	if _, err := e.svc.CreateContact(e.ctx, blind, e.acme, docs.ContactInput{Name: "X"}); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("without doc.manage, an addition: %v", err)
	}
	// A site's grant with a scope that reaches the organization still
	// lists only the rows the grant reads.
	wide := e.caller(rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: e.acme, SiteID: e.hq})
	wide.Scope = database.Scope{Orgs: []uuid.UUID{e.acme}}
	if list, _, err := e.svc.ListContacts(e.ctx, wide, e.acme, docs.ContactQuery{}); err != nil || !slices.Equal(names(list), []string{"Hal Desk"}) {
		t.Fatalf("a site's grant with a wide scope lists %v %v", err, names(list))
	}

	// Row-level security holds below the service: within Globex's scope
	// Acme's rows are not there, cannot be written, and a Globex row cannot
	// name Acme's site.
	globex := database.Scope{Orgs: []uuid.UUID{e.globex}}
	err = e.db.InTx(e.ctx, globex, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(e.ctx, `SELECT count(*) FROM contacts`).Scan(&n); err != nil || n != 0 {
			t.Errorf("Globex's scope sees %d contacts: %v", n, err)
		}
		tag, err := tx.Exec(e.ctx, `UPDATE contacts SET name = 'X' WHERE id = $1`, own.ID)
		if err != nil || tag.RowsAffected() != 0 {
			t.Errorf("Globex's scope changes Acme's contact: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for what, c := range map[string]struct {
		sql  string
		args []any
		rls  bool
	}{
		"Acme's contact": {`INSERT INTO contacts (organization_id, name) VALUES ($1, 'X')`, []any{e.acme}, true},
		"Globex's contact at Acme's site": {`INSERT INTO contacts (organization_id, site_id, name) VALUES ($1, $2, 'X')`,
			[]any{e.globex, e.hq}, false},
		"Globex's place at Acme's site": {`INSERT INTO site_places (organization_id, site_id, depth, kind, name) VALUES ($1, $2, 1, 'room', 'X')`,
			[]any{e.globex, e.hq}, false},
		"Acme's place": {`INSERT INTO site_places (organization_id, site_id, depth, kind, name) VALUES ($1, $2, 1, 'room', 'X')`,
			[]any{e.acme, e.hq}, true},
	} {
		err := e.db.InTx(e.ctx, globex, func(tx pgx.Tx) error { _, err := tx.Exec(e.ctx, c.sql, c.args...); return err })
		if c.rls && !database.IsRLSViolation(err) || !c.rls && !database.IsForeignKeyViolation(err) {
			t.Errorf("%s within Globex's scope: %v", what, err)
		}
	}
	// A site's scope reaches the site's rows, not the organization's own.
	err = e.db.InTx(e.ctx, database.Scope{Sites: []uuid.UUID{e.hq}, ReadOrgs: []uuid.UUID{e.acme}}, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(e.ctx, `SELECT count(*) FROM contacts`).Scan(&n); err != nil || n != 1 {
			t.Errorf("HQ's scope sees %d contacts: %v", n, err)
		}
		_, err := tx.Exec(e.ctx, `INSERT INTO contacts (organization_id, name) VALUES ($1, 'X')`, e.acme)
		return err
	})
	if !database.IsRLSViolation(err) {
		t.Errorf("HQ's scope adds to the organization: %v", err)
	}
}

func TestPlaces(t *testing.T) {
	e := newEnv(t)
	main := e.place(e.sys, e.hq, nil, "building", " Main\tbuilding ")
	if main.Name != "Main building" || main.Depth != 1 || main.ParentID != nil || main.OrganizationID != e.acme {
		t.Fatalf("a building %+v", main)
	}
	ground := e.place(e.sys, e.hq, &main.ID, "floor", "Ground")
	first := e.place(e.sys, e.hq, &main.ID, "floor", "First")
	server := e.place(e.sys, e.hq, &ground.ID, "room", "Server room")
	rack := e.place(e.sys, e.hq, &server.ID, "rack", "Rack A")
	if rack.Depth != 4 || *rack.ParentID != server.ID {
		t.Fatalf("a rack %+v", rack)
	}
	annex := e.place(e.sys, e.hq, nil, "building", "Annex")

	for name, c := range map[string]struct {
		in    docs.PlaceInput
		field string
	}{
		"too deep":         {docs.PlaceInput{ParentID: &rack.ID, Kind: "other", Name: "Shelf"}, "parentId"},
		"same name, place": {docs.PlaceInput{ParentID: &main.ID, Kind: "floor", Name: "GROUND"}, "name"},
		"same name, top":   {docs.PlaceInput{Kind: "building", Name: "annex"}, "name"},
		"bad kind":         {docs.PlaceInput{Kind: "cupboard", Name: "X"}, "kind"},
		"no name":          {docs.PlaceInput{Kind: "room", Name: "\n"}, "name"},
		"long name":        {docs.PlaceInput{Kind: "room", Name: strings.Repeat("r", 201)}, "name"},
		"missing parent":   {docs.PlaceInput{ParentID: ptr(uuid.New()), Kind: "room", Name: "X"}, "parentId"},
		"another site's":   {docs.PlaceInput{ParentID: ptr(e.place(e.sys, e.branch, nil, "building", "Depot").ID), Kind: "room", Name: "X"}, "parentId"},
	} {
		_, err := e.svc.CreatePlace(e.ctx, e.sys, e.hq, c.in)
		wantField(t, err, c.field, name)
	}
	// The same name in another place is another place.
	upstairs := e.place(e.sys, e.hq, &first.ID, "room", "Server room")
	if _, err := e.svc.CreatePlace(e.ctx, e.sys, uuid.New(), docs.PlaceInput{Kind: "room", Name: "X"}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("a place at no site: %v", err)
	}

	tree := func() string {
		t.Helper()
		list, err := e.svc.ListPlaces(e.ctx, e.sys, e.hq)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, p := range list {
			out = append(out, strings.Repeat("-", p.Depth-1)+p.Name)
		}
		return strings.Join(out, ",")
	}
	if got := tree(); got != "Annex,Main building,-First,--Server room,-Ground,--Server room,---Rack A" {
		t.Fatalf("tree %s", got)
	}

	// Moving takes the places inside along, within the four levels, never
	// into itself or another site.
	if _, err := e.svc.UpdatePlace(e.ctx, e.sys, ground.ID, docs.PlacePatch{ParentID: docs.OptionalID{Set: true, ID: &annex.ID}}); err != nil {
		t.Fatal(err)
	}
	if got := tree(); got != "Annex,-Ground,--Server room,---Rack A,Main building,-First,--Server room" {
		t.Fatalf("after moving a floor %s", got)
	}
	top, err := e.svc.UpdatePlace(e.ctx, e.sys, server.ID, docs.PlacePatch{ParentID: docs.OptionalID{Set: true}, Name: ptr("Comms room")})
	if err != nil || top.Depth != 1 || top.ParentID != nil || top.Name != "Comms room" {
		t.Fatalf("to the top %v %+v", err, top)
	}
	if got := tree(); got != "Annex,-Ground,Comms room,-Rack A,Main building,-First,--Server room" {
		t.Fatalf("after moving a room to the top %s", got)
	}
	for name, c := range map[string]struct {
		id     uuid.UUID
		parent uuid.UUID
	}{
		"into itself":     {annex.ID, annex.ID},
		"into its own":    {annex.ID, ground.ID},
		"five deep":       {server.ID, upstairs.ID}, // the Comms room's rack would be fifth
		"another site's":  {annex.ID, e.place(e.sys, e.branch, nil, "building", "Store").ID},
		"a missing place": {annex.ID, uuid.New()},
	} {
		_, err := e.svc.UpdatePlace(e.ctx, e.sys, c.id, docs.PlacePatch{ParentID: docs.OptionalID{Set: true, ID: &c.parent}})
		wantField(t, err, "parentId", name)
	}
	if _, err := e.svc.UpdatePlace(e.ctx, e.sys, server.ID, docs.PlacePatch{ParentID: docs.OptionalID{Set: true, ID: &ground.ID}}); err != nil {
		t.Fatalf("a room with its rack under a floor: %v", err)
	}
	_, err = e.svc.UpdatePlace(e.ctx, e.sys, annex.ID, docs.PlacePatch{Name: ptr("main BUILDING")})
	wantField(t, err, "name", "rename to a taken name")
	_, err = e.svc.UpdatePlace(e.ctx, e.sys, annex.ID, docs.PlacePatch{Kind: ptr("garage")})
	wantField(t, err, "kind", "a bad kind")
	before := len(e.entries("site_place.update"))
	if _, err := e.svc.UpdatePlace(e.ctx, e.sys, annex.ID, docs.PlacePatch{Name: ptr("Annex"), Kind: ptr("building"), ParentID: docs.OptionalID{Set: true}}); err != nil {
		t.Fatal(err)
	}
	if len(e.entries("site_place.update")) != before {
		t.Fatal("a change that changed nothing was recorded")
	}
	if _, err := e.svc.UpdatePlace(e.ctx, e.sys, uuid.New(), docs.PlacePatch{Name: ptr("X")}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("change a missing place: %v", err)
	}

	// A place with places inside is not deleted.
	err = e.svc.DeletePlace(e.ctx, e.sys, annex.ID)
	wantCode(t, err, apperr.KindConflict, "place_not_empty", "delete a building with floors")
	if err := e.svc.DeletePlace(e.ctx, e.sys, rack.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeletePlace(e.ctx, e.sys, rack.ID); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("delete again: %v", err)
	}

	// The audit log has the kind and the parent, never a name.
	for _, en := range e.entries("site_place") {
		b, _ := json.Marshal(en.Details)
		for _, name := range []string{"Main", "Annex", "Ground", "Comms", "Rack A", "Server room"} {
			if strings.Contains(string(b), name) {
				t.Errorf("%s holds a name: %s", en.Action, b)
			}
		}
		if en.Details["kind"] == nil {
			t.Errorf("%s lacks the kind: %s", en.Action, b)
		}
		if en.SiteID == nil || (*en.SiteID != e.hq && *en.SiteID != e.branch) {
			t.Errorf("%s is not filed under its site", en.Action)
		}
	}

	// At most 500 a site.
	if err := e.db.InTx(e.ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(e.ctx, `INSERT INTO site_places (organization_id, site_id, depth, kind, name)
			SELECT $1, $2, 1, 'room', 'Room ' || n FROM generate_series(1, 500) n`, e.globex, e.plant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.CreatePlace(e.ctx, e.sys, e.plant, docs.PlaceInput{Kind: "room", Name: "One more"})
	wantCode(t, err, apperr.KindConflict, "too_many_places", "past the limit")
}

func TestPlaceAccess(t *testing.T) {
	e := newEnv(t)
	hq := e.place(e.sys, e.hq, nil, "building", "Main")
	branch := e.place(e.sys, e.branch, nil, "building", "Depot")

	other := e.caller(rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: e.globex})
	tech := e.caller(rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: e.acme, SiteID: e.hq})
	ro := e.caller(rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: e.acme})
	blind := e.caller(rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: e.globex})
	blind.Scope = database.Scope{Orgs: []uuid.UUID{e.acme, e.globex}}

	notFound := map[string]struct {
		c     access.Caller
		site  uuid.UUID
		place uuid.UUID
	}{"another organization's administrator": {other, e.hq, hq.ID}, "a site's technician at another site": {tech, e.branch, branch.ID}}
	for who, x := range notFound {
		if _, err := e.svc.ListPlaces(e.ctx, x.c, x.site); !errors.Is(err, apperr.ErrNotFound) {
			t.Fatalf("%s lists: %v", who, err)
		}
		if _, err := e.svc.CreatePlace(e.ctx, x.c, x.site, docs.PlaceInput{Kind: "room", Name: "X"}); !errors.Is(err, apperr.ErrNotFound) {
			t.Fatalf("%s adds: %v", who, err)
		}
		if _, err := e.svc.UpdatePlace(e.ctx, x.c, x.place, docs.PlacePatch{Name: ptr("X")}); !errors.Is(err, apperr.ErrNotFound) {
			t.Fatalf("%s changes: %v", who, err)
		}
		if err := e.svc.DeletePlace(e.ctx, x.c, x.place); !errors.Is(err, apperr.ErrNotFound) {
			t.Fatalf("%s deletes: %v", who, err)
		}
	}
	forbidden := map[string]access.Caller{"Read-Only": ro, "a role without doc.view": blind}
	for who, c := range forbidden {
		if _, err := e.svc.CreatePlace(e.ctx, c, e.hq, docs.PlaceInput{Kind: "room", Name: "X"}); !errors.Is(err, apperr.ErrForbidden) {
			t.Fatalf("%s adds: %v", who, err)
		}
		if _, err := e.svc.UpdatePlace(e.ctx, c, hq.ID, docs.PlacePatch{Name: ptr("X")}); !errors.Is(err, apperr.ErrForbidden) {
			t.Fatalf("%s changes: %v", who, err)
		}
		if err := e.svc.DeletePlace(e.ctx, c, hq.ID); !errors.Is(err, apperr.ErrForbidden) {
			t.Fatalf("%s deletes: %v", who, err)
		}
	}
	if _, err := e.svc.ListPlaces(e.ctx, blind, e.hq); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("a role without doc.view lists: %v", err)
	}
	if list, err := e.svc.ListPlaces(e.ctx, ro, e.hq); err != nil || len(list) != 1 {
		t.Fatalf("Read-Only lists %v %+v", err, list)
	}
	room := e.place(tech, e.hq, &hq.ID, "room", "Office")
	if _, err := e.svc.UpdatePlace(e.ctx, tech, room.ID, docs.PlacePatch{Kind: ptr("other")}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeletePlace(e.ctx, tech, room.ID); err != nil {
		t.Fatal(err)
	}
}

// TestCounts counts what a site and an organization hold, as deleting them
// asks.
func TestCounts(t *testing.T) {
	e := newEnv(t)
	e.contact(e.sys, e.acme, docs.ContactInput{Name: "Ann Example"})
	e.contact(e.sys, e.acme, docs.ContactInput{SiteID: &e.hq, Name: "Hal Desk"})
	e.contact(e.sys, e.acme, docs.ContactInput{SiteID: &e.hq, Name: "Hal Two"})
	b := e.place(e.sys, e.hq, nil, "building", "Main")
	e.place(e.sys, e.hq, &b.ID, "floor", "Ground")
	err := e.db.ReadTx(e.ctx, database.System, func(tx pgx.Tx) error {
		site, err := docs.SiteCounts(e.ctx, tx, e.hq)
		if err != nil || site["contacts"] != 2 || site["places"] != 2 {
			t.Errorf("HQ holds %v %v", site, err)
		}
		org, err := docs.OrganizationCounts(e.ctx, tx, e.acme)
		if err != nil || org["contacts"] != 1 || org["places"] != 0 {
			t.Errorf("Acme holds %v %v", org, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Deleting the site takes its places, the deepest with the rest.
	if err := e.db.InTx(e.ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(e.ctx, `DELETE FROM sites WHERE id = $1`, e.hq)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM site_places`) + e.count(`SELECT count(*) FROM contacts WHERE site_id IS NOT NULL`); n != 0 {
		t.Fatalf("%d rows outlived their site", n)
	}
}

// TestConcurrentEdits checks that a change is applied to the record as it
// is once its level is locked, not as the caller read it (L1), and that
// what the database refuses under a writer that skips the lock is a
// conflict, not a server error.
func TestConcurrentEdits(t *testing.T) {
	e := newEnv(t)
	lockHQ := func(tx pgx.Tx) error {
		_, err := tx.Exec(e.ctx, `SELECT 1 FROM sites WHERE id = $1 FOR NO KEY UPDATE`, e.hq)
		return err
	}
	exec := func(tx pgx.Tx, sql string, args ...any) error {
		_, err := tx.Exec(e.ctx, sql, args...)
		return err
	}
	state := func(id uuid.UUID) string {
		t.Helper()
		var s string
		if err := e.db.ReadTx(e.ctx, database.System, func(tx pgx.Tx) error {
			return tx.QueryRow(e.ctx, `SELECT priority || ' ' || mobile_phone FROM contacts WHERE id = $1`, id).Scan(&s)
		}); err != nil {
			t.Fatal(err)
		}
		return s
	}

	// Ann was the site's primary contact when her phone number was edited;
	// Bob became it before the edit was saved. The edit keeps Bob's place.
	ann := e.contact(e.sys, e.acme, docs.ContactInput{SiteID: &e.hq, Name: "Ann Example", Priority: "primary", MobilePhone: "555 0101"})
	bob := e.contact(e.sys, e.acme, docs.ContactInput{SiteID: &e.hq, Name: "Bob Example"})
	err := e.raced(func(tx pgx.Tx) error {
		if err := lockHQ(tx); err != nil {
			return err
		}
		return exec(tx, `UPDATE contacts SET priority = CASE WHEN id = $1 THEN 'secondary' ELSE 'primary' END WHERE id IN ($1, $2)`, ann.ID, bob.ID)
	}, func() error {
		_, err := e.svc.UpdateContact(e.ctx, e.sys, ann.ID, docs.ContactPatch{MobilePhone: ptr("555 0199")})
		return err
	})
	if err != nil {
		t.Fatalf("an edit after another made a new primary: %v", err)
	}
	if a, b := state(ann.ID), state(bob.ID); a != "secondary 555 0199" || b != "primary " {
		t.Fatalf("Ann %q, Bob %q", a, b)
	}
	if f, _ := json.Marshal(e.entries("contact.update")[0].Details); string(f) != `{"emergency":false,"fields":["mobilePhone"],"priority":"secondary"}` {
		t.Fatalf("the edit's audit details %s", f)
	}

	// Making Ann primary again while the lock is held demotes Bob, who is
	// the primary contact by the time the change is made.
	err = e.raced(lockHQ, func() error {
		_, err := e.svc.UpdateContact(e.ctx, e.sys, ann.ID, docs.ContactPatch{Priority: ptr("primary")})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if a, b := state(ann.ID), state(bob.ID); a != "primary 555 0199" || b != "secondary " {
		t.Fatalf("Ann %q, Bob %q", a, b)
	}
	updates := e.entries("contact.update")
	if d := updates[0].Details; d["previousPrimaryId"] != bob.ID.String() {
		t.Fatalf("the demotion is not recorded: %v", d)
	}
	// Bob's own record, at his site, names the contact that replaced him.
	if b := updates[1]; b.TargetID != bob.ID.String() || b.SiteID == nil || *b.SiteID != e.hq ||
		b.Details["priority"] != "secondary" || b.Details["primaryId"] != ann.ID.String() {
		t.Fatalf("Bob's demotion record %+v", b)
	}

	// A second primary written by something that skips the lock, such as a
	// restore, is a conflict.
	err = e.raced(func(tx pgx.Tx) error {
		return exec(tx, `INSERT INTO contacts (organization_id, site_id, name, priority) VALUES ($1, $2, 'Dee Example', 'primary')`, e.acme, e.branch)
	}, func() error {
		_, err := e.svc.CreateContact(e.ctx, e.sys, e.acme, docs.ContactInput{SiteID: &e.branch, Name: "Eve Example", Priority: "primary"})
		return err
	})
	wantCode(t, err, apperr.KindConflict, "primary_changed", "a second primary written past the lock")

	// Main has Floor 1 in it, and Annex is beside it. Floor 1 was moved to
	// the top while another person moved it into Annex: the second move
	// starts from where the first left it.
	main := e.place(e.sys, e.hq, nil, "building", "Main")
	floor := e.place(e.sys, e.hq, &main.ID, "floor", "Floor 1")
	room := e.place(e.sys, e.hq, &floor.ID, "room", "Room 101")
	annex := e.place(e.sys, e.hq, nil, "building", "Annex")
	err = e.raced(func(tx pgx.Tx) error {
		if err := lockHQ(tx); err != nil {
			return err
		}
		return exec(tx, `WITH RECURSIVE sub AS (SELECT id FROM site_places WHERE id = $1
				UNION ALL SELECT p.id FROM site_places p JOIN sub ON p.parent_id = sub.id)
			UPDATE site_places SET depth = depth - 1, parent_id = CASE WHEN id = $1 THEN NULL ELSE parent_id END
			WHERE id IN (SELECT id FROM sub)`, floor.ID)
	}, func() error {
		_, err := e.svc.UpdatePlace(e.ctx, e.sys, floor.ID, docs.PlacePatch{ParentID: docs.OptionalID{Set: true, ID: &annex.ID}})
		return err
	})
	if err != nil {
		t.Fatalf("a move after another: %v", err)
	}
	places, err := e.svc.ListPlaces(e.ctx, e.sys, e.hq)
	if err != nil {
		t.Fatal(err)
	}
	depths := map[uuid.UUID]int{}
	for _, p := range places {
		depths[p.ID] = p.Depth
	}
	if depths[floor.ID] != 2 || depths[room.ID] != 3 {
		t.Fatalf("depths after two moves: %v", depths)
	}

	// A parent deleted by something that skips the lock is a conflict.
	err = e.raced(func(tx pgx.Tx) error {
		return exec(tx, `DELETE FROM site_places WHERE id = $1`, main.ID)
	}, func() error {
		_, err := e.svc.UpdatePlace(e.ctx, e.sys, room.ID, docs.PlacePatch{ParentID: docs.OptionalID{Set: true, ID: &main.ID}})
		return err
	})
	wantCode(t, err, apperr.KindConflict, "places_changed", "a move into a place deleted past the lock")
}
