// Package assets keeps the asset record (ADR-0066, slice 2): one record per
// piece of hardware, linked to at most one device, with each identifying
// field's value kept per source (the agent, entered by hand) and the
// effective value derived from them; and an organization's age policy.
//
// Every query runs in the caller's row-level security scope. doc.view reads
// and doc.manage changes, each checked at the asset's site. New behavior
// (copying the agent's values into asset records) is held back by
// devscope.Allowed.
package assets

import (
	"context"
	"errors"
	"fmt"
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

// Service keeps asset records.
type Service struct {
	db    *database.DB
	audit *audit.Logger
}

// New builds the service.
func New(db *database.DB, auditLog *audit.Logger) *Service {
	return &Service{db: db, audit: auditLog}
}

// SourceValue is what one source says of a field.
type SourceValue struct {
	Source     string     `json:"source"`
	Value      string     `json:"value"`
	State      string     `json:"state"`
	Reason     string     `json:"reason,omitempty"`
	ObservedAt *time.Time `json:"observedAt,omitempty"`
	RecordedAt time.Time  `json:"recordedAt"`
}

// FieldView is a field with the values of each source and the one that
// decides.
type FieldView struct {
	Field     string        `json:"field"`
	Label     string        `json:"label"`
	Effective string        `json:"effective"`
	Sources   []SourceValue `json:"sources"`
	// Differs is true when a person's value and the agent's reported one
	// are both set and unequal.
	Differs bool `json:"differs"`
	// Editable says the field accepts a manual value.
	Editable bool `json:"editable"`
}

// Asset is one record.
type Asset struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"organizationId"`
	SiteID         uuid.UUID  `json:"siteId"`
	SiteName       string     `json:"siteName"`
	DeviceID       *uuid.UUID `json:"deviceId"`
	DeviceName     string     `json:"deviceName,omitempty"`
	Kind           string     `json:"kind"`
	Status         string     `json:"status"`
	Name           string     `json:"name"`
	Manufacturer   string     `json:"manufacturer"`
	Model          string     `json:"model"`
	SerialNumber   string     `json:"serialNumber"`
	SKU            string     `json:"sku"`
	ChassisType    string     `json:"chassisType"`
	AssetTag       string     `json:"assetTag"`
	SMBIOSUUID     string     `json:"smbiosUuid"`
	PurchaseDate   *string    `json:"purchaseDate"`
	WarrantyExpiry *string    `json:"warrantyExpiry"`
	WarrantyStatus string     `json:"warrantyStatus"`
	OSEOLDate      *string    `json:"osEolDate"`
	Notes          string     `json:"notes"`
	// WarrantyState is judged from the expiry date: active, expiring,
	// expired, or empty. AgeStatus from the purchase date and the
	// organization's policy: ok, aging, end_of_life, or empty. OSSupport
	// from the end-of-support date: supported, ending, ended, or empty.
	WarrantyState string      `json:"warrantyState"`
	AgeStatus     string      `json:"ageStatus"`
	OSSupport     string      `json:"osSupport"`
	Fields        []FieldView `json:"fields,omitempty"`
	CanManage     bool        `json:"canManage"`
	CreatedAt     time.Time   `json:"createdAt"`
	UpdatedAt     time.Time   `json:"updatedAt"`
}

// AgePolicy is an organization's thresholds, in months from purchase.
type AgePolicy struct {
	AgingMonths int `json:"agingMonths"`
	EOLMonths   int `json:"eolMonths"`
}

// DefaultAgePolicy applies where an organization has set none.
var DefaultAgePolicy = AgePolicy{AgingMonths: 36, EOLMonths: 60}

// Input is a new asset. Fields are manual values.
type Input struct {
	SiteID   uuid.UUID         `json:"siteId"`
	DeviceID *uuid.UUID        `json:"deviceId"`
	Kind     string            `json:"kind"`
	Status   string            `json:"status"`
	Notes    string            `json:"notes"`
	Fields   map[string]string `json:"fields"`
	// ConfirmDuplicateSerial saves an asset whose serial is already
	// recorded in the organization.
	ConfirmDuplicateSerial bool `json:"confirmDuplicateSerial"`
}

// Patch changes what it names. A field set to null, or to an empty string,
// removes its manual value, which leaves the agent's.
type Patch struct {
	Kind   *string            `json:"kind"`
	Status *string            `json:"status"`
	Notes  *string            `json:"notes"`
	Fields map[string]*string `json:"fields"`
	// ConfirmDuplicateSerial saves a serial already recorded in the
	// organization.
	ConfirmDuplicateSerial bool `json:"confirmDuplicateSerial"`
}

// Query selects assets of an organization.
type Query struct {
	SiteID, GroupID uuid.UUID
	Kind, Status    string
	Search          string
	// Warranty is one of expired, expiring, active, none.
	Warranty string
	// Age is one of ok, aging, end_of_life.
	Age    string
	Sort   string
	Desc   bool
	Offset int
	Limit  int
}

// MaxLimit is the most assets one page holds.
const MaxLimit = 200

var sortColumns = map[string]string{
	"name": "lower(a.name)", "manufacturer": "lower(a.manufacturer)", "model": "lower(a.model)",
	"serial_number": "a.serial_key", "asset_tag": "lower(a.asset_tag)", "kind": "a.kind", "status": "a.status",
	"site": "lower(s.name)", "purchase_date": "a.purchase_date", "warranty_expiry": "a.warranty_expiry",
	"os_eol_date": "a.os_eol_date",
}

const assetColumns = `a.id, a.organization_id, a.site_id, s.name, a.device_id, coalesce(d.name, ''), a.kind, a.status, a.name,
	a.manufacturer, a.model, a.serial_number, a.sku, a.chassis_type, a.asset_tag, a.smbios_uuid,
	a.purchase_date, a.warranty_expiry, a.warranty_status, a.os_eol_date, a.notes, a.created_at, a.updated_at`

const assetFrom = ` FROM assets a JOIN sites s ON s.id = a.site_id LEFT JOIN devices d ON d.id = a.device_id`

func dateString(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.Format(time.DateOnly)
	return &s
}

func (s *Service) scan(row pgx.Row, pol AgePolicy, now time.Time) (Asset, error) {
	var a Asset
	var purchase, expiry, eol *time.Time
	err := row.Scan(&a.ID, &a.OrganizationID, &a.SiteID, &a.SiteName, &a.DeviceID, &a.DeviceName, &a.Kind, &a.Status, &a.Name,
		&a.Manufacturer, &a.Model, &a.SerialNumber, &a.SKU, &a.ChassisType, &a.AssetTag, &a.SMBIOSUUID,
		&purchase, &expiry, &a.WarrantyStatus, &eol, &a.Notes, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return a, err
	}
	a.PurchaseDate, a.WarrantyExpiry, a.OSEOLDate = dateString(purchase), dateString(expiry), dateString(eol)
	a.WarrantyState = WarrantyState(expiry, now)
	a.AgeStatus = AgeStatus(purchase, pol, now)
	switch ws := WarrantyState(eol, now); ws {
	case "active":
		a.OSSupport = "supported"
	case "expiring":
		a.OSSupport = "ending"
	case "expired":
		a.OSSupport = "ended"
	}
	return a, nil
}

func policyOf(ctx context.Context, tx pgx.Tx, org uuid.UUID) (AgePolicy, error) {
	p := DefaultAgePolicy
	err := tx.QueryRow(ctx, `SELECT aging_months, eol_months FROM asset_age_policies WHERE organization_id = $1`, org).Scan(&p.AgingMonths, &p.EOLMonths)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultAgePolicy, nil
	}
	return p, err
}

// List returns a page of an organization's assets the caller may read.
func (s *Service) List(ctx context.Context, c access.Caller, org uuid.UUID, q Query) ([]Asset, int, error) {
	if q.SiteID != uuid.Nil {
		if err := c.Require(rbac.PermDocView, rbac.Site(org, q.SiteID)); err != nil {
			return nil, 0, err
		}
	} else if err := c.Require(rbac.PermDocView, rbac.Org(org)); err != nil {
		return nil, 0, err
	}
	f := apperr.Fields{}
	f.Check(q.Kind == "" || slices.Contains(Kinds, q.Kind), "kind", "Unknown kind.")
	f.Check(q.Status == "" || slices.Contains(Statuses, q.Status), "status", "Unknown status.")
	f.Check(q.Warranty == "" || slices.Contains([]string{"expired", "expiring", "active", "none"}, q.Warranty), "warranty", "Use expired, expiring, active or none.")
	f.Check(q.Age == "" || slices.Contains([]string{"ok", "aging", "end_of_life"}, q.Age), "age", "Use ok, aging or end_of_life.")
	col, ok := sortColumns[cmpSort(q.Sort)]
	f.Check(ok, "sort", "Unknown sort.")
	if err := f.Err(); err != nil {
		return nil, 0, err
	}
	var out []Asset
	var total int
	now := time.Now().UTC()
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		pol, err := policyOf(ctx, tx, org)
		if err != nil {
			return err
		}
		where, args := []string{"a.organization_id = $1"}, []any{org}
		add := func(cond string, v any) {
			args = append(args, v)
			where = append(where, strings.ReplaceAll(cond, "?", fmt.Sprintf("$%d", len(args))))
		}
		if q.SiteID != uuid.Nil {
			add("a.site_id = ?", q.SiteID)
		}
		if q.GroupID != uuid.Nil {
			add("d.device_group_id = ?", q.GroupID)
		}
		if q.Kind != "" {
			add("a.kind = ?", q.Kind)
		}
		if q.Status != "" {
			add("a.status = ?", q.Status)
		}
		if q.Search != "" {
			add(`(a.name ILIKE ? ESCAPE '\' OR a.manufacturer ILIKE ? ESCAPE '\' OR a.model ILIKE ? ESCAPE '\' OR a.serial_number ILIKE ? ESCAPE '\' OR a.asset_tag ILIKE ? ESCAPE '\')`,
				"%"+likeEscape(cleanValue(q.Search))+"%")
		}
		switch q.Warranty {
		case "none":
			where = append(where, "a.warranty_expiry IS NULL")
		case "expired":
			where = append(where, "a.warranty_expiry < current_date")
		case "expiring":
			where = append(where, "a.warranty_expiry >= current_date AND a.warranty_expiry < current_date + 91")
		case "active":
			where = append(where, "a.warranty_expiry >= current_date + 91")
		}
		switch q.Age {
		case "end_of_life":
			add("a.purchase_date + make_interval(months => ?) <= current_date", pol.EOLMonths)
		case "aging":
			add("a.purchase_date + make_interval(months => ?) <= current_date", pol.AgingMonths)
			add("a.purchase_date + make_interval(months => ?) > current_date", pol.EOLMonths)
		case "ok":
			add("a.purchase_date + make_interval(months => ?) > current_date", pol.AgingMonths)
		}
		cond := strings.Join(where, " AND ")
		if err := tx.QueryRow(ctx, `SELECT count(*)`+assetFrom+` WHERE `+cond, args...).Scan(&total); err != nil {
			return err
		}
		dir := "ASC"
		if q.Desc {
			dir = "DESC"
		}
		limit := min(max(q.Limit, 1), MaxLimit)
		rows, err := tx.Query(ctx, fmt.Sprintf(`SELECT %s%s WHERE %s ORDER BY %s %s NULLS LAST, a.id LIMIT %d OFFSET %d`,
			assetColumns, assetFrom, cond, col, dir, limit, max(q.Offset, 0)), args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			a, err := s.scan(rows, pol, now)
			if err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, 0, err
	}
	for i := range out {
		out[i].CanManage = c.Can(rbac.PermDocManage, rbac.Site(org, out[i].SiteID))
	}
	return out, total, nil
}

func cmpSort(s string) string {
	if s == "" {
		return "name"
	}
	return s
}

func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// Get returns an asset with each field's values.
func (s *Service) Get(ctx context.Context, c access.Caller, id uuid.UUID) (*Asset, error) {
	return s.get(ctx, c, `a.id = $1`, id)
}

// ForDevice returns the asset linked to a device, apperr.NotFound when it
// has none.
func (s *Service) ForDevice(ctx context.Context, c access.Caller, deviceID uuid.UUID) (*Asset, error) {
	return s.get(ctx, c, `a.device_id = $1`, deviceID)
}

func (s *Service) get(ctx context.Context, c access.Caller, cond string, arg uuid.UUID) (*Asset, error) {
	var a Asset
	var vals []valueRow
	now := time.Now().UTC()
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var org uuid.UUID
		// The policy is the asset's organization's: read it after the row.
		row, err := s.scan(tx.QueryRow(ctx, `SELECT `+assetColumns+assetFrom+` WHERE `+cond, arg), DefaultAgePolicy, now)
		if err != nil {
			return err
		}
		a, org = row, row.OrganizationID
		pol, err := policyOf(ctx, tx, org)
		if err != nil {
			return err
		}
		if a.PurchaseDate != nil {
			t, _ := time.Parse(time.DateOnly, *a.PurchaseDate)
			a.AgeStatus = AgeStatus(&t, pol, now)
		}
		vals, err = readValues(ctx, tx, a.ID)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	if err != nil {
		return nil, err
	}
	where := rbac.Site(a.OrganizationID, a.SiteID)
	if err := c.Require(rbac.PermDocView, where); err != nil {
		return nil, err
	}
	a.CanManage = c.Can(rbac.PermDocManage, where)
	a.Fields = fieldViews(vals)
	return &a, nil
}

type valueRow struct {
	Field string
	SourceValue
}

func readValues(ctx context.Context, tx pgx.Tx, id uuid.UUID) ([]valueRow, error) {
	rows, err := tx.Query(ctx, `SELECT field, source, value, state, reason, observed_at, recorded_at FROM asset_field_values WHERE asset_id = $1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []valueRow
	for rows.Next() {
		var v valueRow
		if err := rows.Scan(&v.Field, &v.Source, &v.Value, &v.State, &v.Reason, &v.ObservedAt, &v.RecordedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func fieldViews(vals []valueRow) []FieldView {
	out := make([]FieldView, 0, len(Catalogue))
	for _, f := range Catalogue {
		v := FieldView{Field: f.Name, Label: f.Label, Editable: true, Sources: []SourceValue{}}
		by := map[string]sourceValue{}
		for _, r := range vals {
			if r.Field == f.Name {
				v.Sources = append(v.Sources, r.SourceValue)
				by[r.Source] = sourceValue{Value: r.Value, State: r.State}
			}
		}
		slices.SortFunc(v.Sources, func(a, b SourceValue) int { return strings.Compare(a.Source, b.Source) })
		v.Effective = effective(f, by)
		ag, man := by[SourceAgent], by[SourceManual]
		v.Differs = ag.State == "reported" && ag.Value != "" && man.Value != "" && !strings.EqualFold(ag.Value, man.Value)
		out = append(out, v)
	}
	return out
}

// refresh derives the asset's effective columns and keys from its values.
// The only writer of them.
func refresh(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	vals, err := readValues(ctx, tx, id)
	if err != nil {
		return err
	}
	by := map[string]map[string]sourceValue{}
	for _, r := range vals {
		if by[r.Field] == nil {
			by[r.Field] = map[string]sourceValue{}
		}
		by[r.Field][r.Source] = sourceValue{Value: r.Value, State: r.State}
	}
	eff := map[string]string{}
	for _, f := range Catalogue {
		eff[f.Name] = effective(f, by[f.Name])
	}
	_, err = tx.Exec(ctx, `UPDATE assets SET name = $2, manufacturer = $3, model = $4, serial_number = $5, sku = $6, chassis_type = $7,
		asset_tag = $8, smbios_uuid = $9, purchase_date = NULLIF($10, '')::date, warranty_expiry = NULLIF($11, '')::date,
		warranty_status = $12, os_eol_date = NULLIF($13, '')::date, serial_key = $14, maker_key = $15 WHERE id = $1`,
		id, eff["name"], eff["manufacturer"], eff["model"], eff["serial_number"], eff["sku"], eff["chassis_type"],
		eff["asset_tag"], eff["smbios_uuid"], eff["purchase_date"], eff["warranty_expiry"], eff["warranty_status"],
		eff["os_eol_date"], SerialKey(eff["serial_number"]), MakerKey(eff["manufacturer"]))
	return err
}

// setManual writes or, for an empty value, removes a manual value.
func setManual(ctx context.Context, tx pgx.Tx, c access.Caller, id, org uuid.UUID, field, value string) error {
	if value == "" {
		_, err := tx.Exec(ctx, `DELETE FROM asset_field_values WHERE asset_id = $1 AND field = $2 AND source = 'manual'`, id, field)
		return err
	}
	var by *uuid.UUID
	if c.Actor.Type == audit.ActorUser {
		by = &c.Actor.ID
	}
	_, err := tx.Exec(ctx, `INSERT INTO asset_field_values (asset_id, organization_id, field, source, value, recorded_by)
		VALUES ($1, $2, $3, 'manual', $4, $5)
		ON CONFLICT (asset_id, field, source) DO UPDATE SET value = $4, recorded_at = now(), recorded_by = $5`,
		id, org, field, value, by)
	return err
}

func checkFields(in map[string]*string) (map[string]string, error) {
	out := map[string]string{}
	f := apperr.Fields{}
	for name, p := range in {
		def, ok := fieldByName(name)
		if !ok {
			f[name] = "Unknown field."
			continue
		}
		v := ""
		if p != nil {
			v = *p
		}
		cv, err := CheckValue(def, v)
		if err != nil {
			var ae *apperr.Error
			if errors.As(err, &ae) {
				f[name] = ae.Message
			}
			continue
		}
		out[name] = cv
	}
	return out, f.Err()
}

func checkNotes(n string) (string, error) {
	n = strings.TrimSpace(strings.ReplaceAll(n, "\r\n", "\n"))
	if len([]rune(n)) > MaxNotesLength {
		return "", apperr.Invalid("notes", "Use at most 4,000 characters.")
	}
	return n, nil
}

func event(c access.Caller, action string, id, org, site uuid.UUID, details map[string]any) audit.Event {
	return audit.Event{Actor: c.Actor, Action: action, Outcome: audit.Success, OrganizationID: org, SiteID: site,
		TargetType: "asset", TargetID: id.String(), Details: details}
}

// duplicateSerial reports another asset of the organization with the same
// serial key.
func duplicateSerial(ctx context.Context, tx pgx.Tx, org, except uuid.UUID, serial string) (bool, error) {
	key := SerialKey(serial)
	if key == "" {
		return false, nil
	}
	var dup bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM assets WHERE organization_id = $1 AND serial_key = $2 AND id <> $3)`, org, key, except).Scan(&dup)
	return dup, err
}

var errDuplicateSerial = apperr.Conflict("duplicate_serial", "An asset with this serial number exists. Save again to confirm.")

// Create makes an asset record by hand, at a site, optionally for a device
// of that site that has none.
func (s *Service) Create(ctx context.Context, c access.Caller, org uuid.UUID, in Input) (*Asset, error) {
	if err := c.Require(rbac.PermDocManage, rbac.Site(org, in.SiteID)); err != nil {
		return nil, err
	}
	if in.Kind == "" {
		in.Kind = "workstation"
	}
	if in.Status == "" {
		in.Status = "in_use"
	}
	f := apperr.Fields{}
	f.Check(slices.Contains(Kinds, in.Kind), "kind", "Unknown kind.")
	f.Check(slices.Contains(Statuses, in.Status), "status", "Unknown status.")
	if err := f.Err(); err != nil {
		return nil, err
	}
	notes, err := checkNotes(in.Notes)
	if err != nil {
		return nil, err
	}
	in2 := map[string]*string{}
	for k, v := range in.Fields {
		in2[k] = &v
	}
	fields, err := checkFields(in2)
	if err != nil {
		return nil, err
	}
	var id uuid.UUID
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM sites WHERE id = $1 AND organization_id = $2)`, in.SiteID, org).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return apperr.NotFound()
		}
		if in.DeviceID != nil {
			var dsite uuid.UUID
			err := tx.QueryRow(ctx, `SELECT site_id FROM devices WHERE id = $1 AND organization_id = $2`, *in.DeviceID, org).Scan(&dsite)
			if errors.Is(err, pgx.ErrNoRows) || (err == nil && dsite != in.SiteID) {
				return apperr.Invalid("deviceId", "Choose a device at this site.")
			}
			if err != nil {
				return err
			}
		}
		if dup, err := duplicateSerial(ctx, tx, org, uuid.Nil, fields["serial_number"]); err != nil {
			return err
		} else if dup && !in.ConfirmDuplicateSerial {
			return errDuplicateSerial
		}
		var by *uuid.UUID
		if c.Actor.Type == audit.ActorUser {
			by = &c.Actor.ID
		}
		if err := tx.QueryRow(ctx, `INSERT INTO assets (organization_id, site_id, device_id, kind, status, notes, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`, org, in.SiteID, in.DeviceID, in.Kind, in.Status, notes, by).Scan(&id); err != nil {
			return err
		}
		for name, v := range fields {
			if v != "" {
				if err := setManual(ctx, tx, c, id, org, name, v); err != nil {
					return err
				}
			}
		}
		if in.DeviceID != nil {
			if err := copyAgentValues(ctx, tx, id, *in.DeviceID); err != nil {
				return err
			}
		}
		if err := refresh(ctx, tx, id); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, event(c, "asset.create", id, org, in.SiteID, map[string]any{"kind": in.Kind, "fields": sortedKeys(fields), "deviceLinked": in.DeviceID != nil}))
	})
	if err != nil {
		return nil, mapWriteError(err)
	}
	return s.Get(ctx, c, id)
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		if v != "" {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

func mapWriteError(err error) error {
	if database.IsUniqueViolation(err) && database.ConstraintName(err) == "assets_device_id_key" {
		return apperr.Conflict("device_has_asset", "This device already has an asset record.")
	}
	return err
}

// CreateForDevice makes the asset record of a device that has none, at the
// device's site, as the agent's values and the device's own describe it.
func (s *Service) CreateForDevice(ctx context.Context, c access.Caller, deviceID uuid.UUID) (*Asset, error) {
	var org, site uuid.UUID
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT organization_id, site_id FROM devices WHERE id = $1`, deviceID).Scan(&org, &site)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	if err != nil {
		return nil, err
	}
	return s.Create(ctx, c, org, Input{SiteID: site, DeviceID: &deviceID, ConfirmDuplicateSerial: true})
}

// Update changes an asset. Manual values are written beside the agent's,
// never over them.
func (s *Service) Update(ctx context.Context, c access.Caller, id uuid.UUID, p Patch) (*Asset, error) {
	cur, err := s.Get(ctx, c, id)
	if err != nil {
		return nil, err
	}
	if err := c.Require(rbac.PermDocManage, rbac.Site(cur.OrganizationID, cur.SiteID)); err != nil {
		return nil, err
	}
	f := apperr.Fields{}
	f.Check(p.Kind == nil || slices.Contains(Kinds, *p.Kind), "kind", "Unknown kind.")
	f.Check(p.Status == nil || slices.Contains(Statuses, *p.Status), "status", "Unknown status.")
	if err := f.Err(); err != nil {
		return nil, err
	}
	fields, err := checkFields(p.Fields)
	if err != nil {
		return nil, err
	}
	changed := map[string]bool{}
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT id FROM assets WHERE id = $1 FOR UPDATE`, id).Scan(&id); err != nil {
			return err
		}
		if p.Kind != nil && *p.Kind != cur.Kind {
			changed["kind"] = true
			if _, err := tx.Exec(ctx, `UPDATE assets SET kind = $2 WHERE id = $1`, id, *p.Kind); err != nil {
				return err
			}
		}
		if p.Status != nil && *p.Status != cur.Status {
			changed["status"] = true
			if _, err := tx.Exec(ctx, `UPDATE assets SET status = $2 WHERE id = $1`, id, *p.Status); err != nil {
				return err
			}
		}
		if p.Notes != nil {
			notes, err := checkNotes(*p.Notes)
			if err != nil {
				return err
			}
			if notes != cur.Notes {
				changed["notes"] = true
				if _, err := tx.Exec(ctx, `UPDATE assets SET notes = $2 WHERE id = $1`, id, notes); err != nil {
					return err
				}
			}
		}
		if serial, ok := fields["serial_number"]; ok && serial != "" {
			if dup, err := duplicateSerial(ctx, tx, cur.OrganizationID, id, serial); err != nil {
				return err
			} else if dup && !p.ConfirmDuplicateSerial {
				return errDuplicateSerial
			}
		}
		for name, v := range fields {
			if err := setManual(ctx, tx, c, id, cur.OrganizationID, name, v); err != nil {
				return err
			}
			changed[name] = true
		}
		if len(changed) == 0 {
			return nil
		}
		if len(fields) > 0 {
			if err := refresh(ctx, tx, id); err != nil {
				return err
			}
		}
		names := make([]string, 0, len(changed))
		for k := range changed {
			names = append(names, k)
		}
		slices.Sort(names)
		return s.audit.Write(ctx, tx, event(c, "asset.update", id, cur.OrganizationID, cur.SiteID, map[string]any{"changed": names}))
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, c, id)
}

// Delete removes an asset record; its device, if any, stays.
func (s *Service) Delete(ctx context.Context, c access.Caller, id uuid.UUID) error {
	cur, err := s.Get(ctx, c, id)
	if err != nil {
		return err
	}
	if err := c.Require(rbac.PermDocManage, rbac.Site(cur.OrganizationID, cur.SiteID)); err != nil {
		return err
	}
	return s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM assets WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return apperr.NotFound()
		}
		return s.audit.Write(ctx, tx, event(c, "asset.delete", id, cur.OrganizationID, cur.SiteID,
			map[string]any{"kind": cur.Kind, "deviceLinked": cur.DeviceID != nil}))
	})
}

// GetPolicy returns the organization's age policy, the default when it has
// set none.
func (s *Service) GetPolicy(ctx context.Context, c access.Caller, org uuid.UUID) (AgePolicy, error) {
	if err := c.Require(rbac.PermDocView, rbac.Org(org)); err != nil {
		return AgePolicy{}, err
	}
	var p AgePolicy
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM organizations WHERE id = $1)`, org).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return apperr.NotFound()
		}
		var err error
		p, err = policyOf(ctx, tx, org)
		return err
	})
	return p, err
}

// SetPolicy sets the organization's age policy.
func (s *Service) SetPolicy(ctx context.Context, c access.Caller, org uuid.UUID, p AgePolicy) (AgePolicy, error) {
	if err := c.Require(rbac.PermDocManage, rbac.Org(org)); err != nil {
		return AgePolicy{}, err
	}
	f := apperr.Fields{}
	f.Check(p.AgingMonths >= 1 && p.AgingMonths <= 240, "agingMonths", "Use 1 to 240 months.")
	f.Check(p.EOLMonths >= 1 && p.EOLMonths <= 240, "eolMonths", "Use 1 to 240 months.")
	f.Check(p.AgingMonths < p.EOLMonths, "agingMonths", "Aging must come before end of life.")
	if err := f.Err(); err != nil {
		return AgePolicy{}, err
	}
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM organizations WHERE id = $1)`, org).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return apperr.NotFound()
		}
		if _, err := tx.Exec(ctx, `INSERT INTO asset_age_policies (organization_id, aging_months, eol_months) VALUES ($1, $2, $3)
			ON CONFLICT (organization_id) DO UPDATE SET aging_months = $2, eol_months = $3`, org, p.AgingMonths, p.EOLMonths); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "asset.policy_update", Outcome: audit.Success, OrganizationID: org,
			TargetType: "organization", TargetID: org.String(), Details: map[string]any{"agingMonths": p.AgingMonths, "eolMonths": p.EOLMonths}})
	})
	return p, err
}
