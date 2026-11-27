//go:build integration

package assets_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/assets"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/tenancy"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

type env struct {
	t                *testing.T
	ctx              context.Context
	db               *database.DB
	super            *pgx.Conn
	svc              *assets.Service
	sys              access.Caller
	acme, hq, branch uuid.UUID
	globex, plant    uuid.UUID
}

func newEnv(t *testing.T) *env {
	t.Helper()
	inst := testdb.New(t)
	al := audit.New(inst.DB, nil)
	e := &env{t: t, ctx: context.Background(), db: inst.DB, svc: assets.New(inst.DB, al), sys: access.System("test")}
	super, err := pgx.Connect(e.ctx, inst.SuperDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(context.Background()) })
	e.super = super
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

func (e *env) caller(a rbac.Assignment) access.Caller {
	e.t.Helper()
	uid := uuid.New()
	p, err := rbac.NewPrincipal(uid, []rbac.Assignment{a})
	if err != nil {
		e.t.Fatal(err)
	}
	return access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: uid, Label: "user@example.com"})
}

func (e *env) device(org, site uuid.UUID, name string) uuid.UUID {
	e.t.Helper()
	var id uuid.UUID
	if err := e.super.QueryRow(e.ctx, `INSERT INTO devices (organization_id, site_id, name) VALUES ($1, $2, $3) RETURNING id`, org, site, name).Scan(&id); err != nil {
		e.t.Fatal(err)
	}
	return id
}

func (e *env) sync(device uuid.UUID, sys agentproto.SystemInfo) {
	e.t.Helper()
	if err := e.db.InTx(e.ctx, database.System, func(tx pgx.Tx) error { return assets.SyncAgent(e.ctx, tx, device, sys) }); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) auditActions() []string {
	e.t.Helper()
	rows, err := e.super.Query(e.ctx, `SELECT action FROM audit_log WHERE action LIKE 'asset.%' ORDER BY id`)
	if err != nil {
		e.t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		e.t.Fatal(err)
	}
	return out
}

func str(s string) *string { return &s }

func TestAgentValuesAndManualNeverOverwrite(t *testing.T) {
	e := newEnv(t)
	dev := e.device(e.acme, e.hq, "pc-1")
	e.sync(dev, agentproto.SystemInfo{Manufacturer: "Dell Inc.", Model: "OptiPlex 7090", Serial: "ABC-123"})
	a, err := e.svc.ForDevice(e.ctx, e.sys, dev)
	if err != nil {
		t.Fatal(err)
	}
	if a.Manufacturer != "Dell Inc." || a.SerialNumber != "ABC-123" || a.Kind != "workstation" || a.Status != "in_use" || a.Name != "pc-1" {
		t.Fatalf("agent values not copied: %+v", a)
	}

	// A person's serial sits beside the agent's, which stays effective.
	a, err = e.svc.Update(e.ctx, e.sys, a.ID, assets.Patch{Fields: map[string]*string{"serial_number": str("XYZ-9"), "asset_tag": str("T-1"), "warranty_expiry": str("2031-01-01")}, ConfirmDuplicateSerial: true})
	if err != nil {
		t.Fatal(err)
	}
	if a.SerialNumber != "ABC-123" || a.AssetTag != "T-1" || a.WarrantyExpiry == nil || *a.WarrantyExpiry != "2031-01-01" {
		t.Fatalf("effective values wrong: %+v", a)
	}
	var differs bool
	for _, f := range a.Fields {
		if f.Field == "serial_number" {
			differs = f.Differs
		}
	}
	if !differs {
		t.Error("serial_number should differ")
	}

	// An inventory upload rewrites the agent's values only.
	e.sync(dev, agentproto.SystemInfo{Manufacturer: "Dell Inc.", Model: "OptiPlex 7090", Serial: "NEW-1"})
	a, _ = e.svc.Get(e.ctx, e.sys, a.ID)
	if a.SerialNumber != "NEW-1" || a.AssetTag != "T-1" {
		t.Fatalf("after upload: %+v", a)
	}
	// An unreadable serial is unknown, never decides, and never differs.
	e.sync(dev, agentproto.SystemInfo{Manufacturer: "Dell Inc.", Model: "OptiPlex 7090"})
	a, _ = e.svc.Get(e.ctx, e.sys, a.ID)
	if a.SerialNumber != "XYZ-9" {
		t.Fatalf("manual should decide when the agent has nothing: %q", a.SerialNumber)
	}
	for _, f := range a.Fields {
		if f.Field == "serial_number" && f.Differs {
			t.Error("unknown agent value must not make a manual one differ")
		}
	}
	// Removing the manual value leaves the agent's (here unknown).
	a, err = e.svc.Update(e.ctx, e.sys, a.ID, assets.Patch{Fields: map[string]*string{"serial_number": nil}})
	if err != nil || a.SerialNumber != "" {
		t.Fatalf("removal: %v %+v", err, a)
	}
	// A second upload makes no second asset.
	var n int
	if err := e.super.QueryRow(e.ctx, `SELECT count(*) FROM assets WHERE device_id = $1`, dev).Scan(&n); err != nil || n != 1 {
		t.Fatalf("assets for device: %d %v", n, err)
	}
}

func TestSyncKindAndRemovedDevice(t *testing.T) {
	e := newEnv(t)
	dev := e.device(e.acme, e.hq, "vm-1")
	e.sync(dev, agentproto.SystemInfo{Virtualization: "kvm", Serial: "S1"})
	a, _ := e.svc.ForDevice(e.ctx, e.sys, dev)
	if a.Kind != "virtual_machine" {
		t.Errorf("kind %q", a.Kind)
	}
	if _, err := e.super.Exec(e.ctx, `DELETE FROM devices WHERE id = $1`, dev); err != nil {
		t.Fatal(err)
	}
	a, err := e.svc.Get(e.ctx, e.sys, a.ID)
	if err != nil || a.DeviceID != nil || a.SerialNumber != "S1" {
		t.Fatalf("asset must outlive its device: %v %+v", err, a)
	}
}

func TestManualCreateListFilterAndAudit(t *testing.T) {
	e := newEnv(t)
	mk := func(site uuid.UUID, tag, serial, purchased, warranty string) *assets.Asset {
		a, err := e.svc.Create(e.ctx, e.sys, e.acme, assets.Input{SiteID: site, Kind: "laptop", Fields: map[string]string{
			"asset_tag": tag, "serial_number": serial, "purchase_date": purchased, "warranty_expiry": warranty, "manufacturer": "HP"}})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	old := mk(e.hq, "A", "SN-1", "2015-01-01", "2016-01-01")
	mk(e.hq, "B", "SN-2", "2024-01-01", "2099-01-01")
	mk(e.branch, "C", "SN-3", "", "")
	if old.AgeStatus != "end_of_life" || old.WarrantyState != "expired" {
		t.Errorf("judgements: %+v", old)
	}
	// The same serial needs a confirmation, matching across spacing and case.
	_, err := e.svc.Create(e.ctx, e.sys, e.acme, assets.Input{SiteID: e.hq, Fields: map[string]string{"serial_number": "sn 1"}})
	var ae *apperr.Error
	if !errors.As(err, &ae) || ae.Code != "duplicate_serial" {
		t.Fatalf("duplicate serial: %v", err)
	}

	list := func(q assets.Query) []string {
		t.Helper()
		q.Limit = 50
		items, _, err := e.svc.List(e.ctx, e.sys, e.acme, q)
		if err != nil {
			t.Fatal(err)
		}
		var tags []string
		for _, a := range items {
			tags = append(tags, a.AssetTag)
		}
		return tags
	}
	if got := list(assets.Query{Sort: "asset_tag"}); !slices.Equal(got, []string{"A", "B", "C"}) {
		t.Errorf("all: %v", got)
	}
	if got := list(assets.Query{SiteID: e.branch}); !slices.Equal(got, []string{"C"}) {
		t.Errorf("site: %v", got)
	}
	if got := list(assets.Query{Warranty: "expired"}); !slices.Equal(got, []string{"A"}) {
		t.Errorf("expired: %v", got)
	}
	if got := list(assets.Query{Warranty: "none"}); !slices.Equal(got, []string{"C"}) {
		t.Errorf("none: %v", got)
	}
	if got := list(assets.Query{Age: "end_of_life"}); !slices.Equal(got, []string{"A"}) {
		t.Errorf("eol: %v", got)
	}
	if got := list(assets.Query{Search: "sn-2"}); !slices.Equal(got, []string{"B"}) {
		t.Errorf("search: %v", got)
	}
	if got := list(assets.Query{Sort: "purchase_date", Desc: true}); got[0] != "B" {
		t.Errorf("sort desc: %v", got)
	}

	// The policy moves the thresholds.
	if _, err := e.svc.SetPolicy(e.ctx, e.sys, e.acme, assets.AgePolicy{AgingMonths: 6, EOLMonths: 12}); err != nil {
		t.Fatal(err)
	}
	if got := list(assets.Query{Age: "end_of_life", Sort: "asset_tag"}); !slices.Equal(got, []string{"A", "B"}) {
		t.Errorf("policy eol: %v", got)
	}
	if _, err := e.svc.SetPolicy(e.ctx, e.sys, e.acme, assets.AgePolicy{AgingMonths: 12, EOLMonths: 6}); err == nil {
		t.Error("inverted policy accepted")
	}

	if err := e.svc.Delete(e.ctx, e.sys, old.ID); err != nil {
		t.Fatal(err)
	}
	want := []string{"asset.create", "asset.create", "asset.create", "asset.policy_update", "asset.delete"}
	if got := e.auditActions(); !slices.Equal(got, want) {
		t.Errorf("audit %v, want %v", got, want)
	}
}

func TestScopesAndPermissions(t *testing.T) {
	e := newEnv(t)
	a, err := e.svc.Create(e.ctx, e.sys, e.acme, assets.Input{SiteID: e.hq, Fields: map[string]string{"asset_tag": "A"}})
	if err != nil {
		t.Fatal(err)
	}
	other, err := e.svc.Create(e.ctx, e.sys, e.acme, assets.Input{SiteID: e.branch})
	if err != nil {
		t.Fatal(err)
	}

	foreign := e.caller(rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: e.globex})
	if _, err := e.svc.Get(e.ctx, foreign, a.ID); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("other organization saw the asset: %v", err)
	}
	if _, _, err := e.svc.List(e.ctx, foreign, e.acme, assets.Query{}); err == nil {
		t.Error("other organization listed the assets")
	}

	hqTech := e.caller(rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: e.acme, SiteID: e.hq})
	if _, err := e.svc.Get(e.ctx, hqTech, other.ID); err == nil {
		t.Error("site-scoped person saw another site's asset")
	}
	items, _, err := e.svc.List(e.ctx, hqTech, e.acme, assets.Query{SiteID: e.hq, Limit: 10})
	if err != nil || len(items) != 1 {
		t.Errorf("site list: %v %d", err, len(items))
	}

	ro := e.caller(rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: e.acme})
	got, err := e.svc.Get(e.ctx, ro, a.ID)
	if err != nil || got.CanManage {
		t.Fatalf("read-only: %v %+v", err, got)
	}
	if _, err := e.svc.Update(e.ctx, ro, a.ID, assets.Patch{Notes: str("x")}); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("read-only update: %v", err)
	}
	if err := e.svc.Delete(e.ctx, ro, a.ID); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("read-only delete: %v", err)
	}
}

func TestValidationAndKeys(t *testing.T) {
	e := newEnv(t)
	bad := []assets.Input{
		{SiteID: e.hq, Kind: "toaster"},
		{SiteID: e.hq, Fields: map[string]string{"purchase_date": "01/02/2020"}},
		{SiteID: e.hq, Fields: map[string]string{"color": "red"}},
		{SiteID: e.hq, Fields: map[string]string{"warranty_status": "maybe"}},
		{SiteID: e.plant},
	}
	for i, in := range bad {
		if _, err := e.svc.Create(e.ctx, e.sys, e.acme, in); err == nil {
			t.Errorf("bad input %d accepted", i)
		}
	}
	if got := assets.SerialKey(" ab-12.c d"); got != "AB12CD" {
		t.Errorf("serial key %q", got)
	}
	for in, want := range map[string]string{"Hewlett-Packard": "hp", "Dell Inc.": "dell", "LENOVO": "lenovo", "Acme Corporation": "acme"} {
		if got := assets.MakerKey(in); got != want {
			t.Errorf("maker key %q = %q, want %q", in, got, want)
		}
	}
}

func TestBackfill(t *testing.T) {
	e := newEnv(t)
	dev := e.device(e.acme, e.hq, "old-pc")
	if _, err := e.super.Exec(e.ctx, `INSERT INTO device_inventory (device_id, hash, data, package_manager, package_count)
		VALUES ($1, repeat('a', 64), '{"system":{"manufacturer":"Lenovo","serial":"L-1"}}', '', 0)`, dev); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Backfill(e.ctx); err != nil {
		t.Fatal(err)
	}
	a, err := e.svc.ForDevice(e.ctx, e.sys, dev)
	if err != nil || a.Manufacturer != "Lenovo" {
		t.Fatalf("backfill: %v %+v", err, a)
	}
}
