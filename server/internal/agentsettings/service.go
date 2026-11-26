package agentsettings

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Audit actions (ADR-0058).
const (
	ActionSet       = "agent_setting.set"
	ActionCleared   = "agent_setting.cleared"
	ActionLimitsSet = "agent_setting.limits_set"
)

// Write limits (ADR-0058): per caller across every scope, and per scope
// target, so a script spread over many sites cannot keep a fleet busy.
const (
	perCallerPerMinute = 60
	perTargetPerMinute = 30
	maxLimiterKeys     = 100000
)

// Service reads and writes agent settings.
type Service struct {
	db       *database.DB
	audit    *audit.Logger
	log      *slog.Logger
	byCaller *auth.KeyedLimiter
	byTarget *auth.KeyedLimiter
}

// New builds the service.
func New(db *database.DB, auditLog *audit.Logger, log *slog.Logger) *Service {
	return &Service{
		db: db, audit: auditLog, log: log,
		byCaller: auth.NewKeyedLimiter(time.Minute/perCallerPerMinute, perCallerPerMinute, maxLimiterKeys),
		byTarget: auth.NewKeyedLimiter(time.Minute/perTargetPerMinute, perTargetPerMinute, maxLimiterKeys),
	}
}

// Target is the organization, site, device or platform a value is set for.
type Target struct {
	Scope    Scope
	OrgID    uuid.UUID
	SiteID   uuid.UUID
	DeviceID uuid.UUID
	Name     string
}

func (t Target) id() uuid.UUID {
	switch t.Scope {
	case ScopeOrganization:
		return t.OrgID
	case ScopeSite:
		return t.SiteID
	case ScopeDevice:
		return t.DeviceID
	}
	return uuid.Nil
}

// resource is what permissions are checked against: the platform needs a
// global grant, an organization an organization-wide one, a site or one of
// its devices a grant at that site (ADR-0017's rule).
func (t Target) resource() rbac.Resource {
	switch t.Scope {
	case ScopeOrganization:
		return rbac.Org(t.OrgID)
	case ScopeSite, ScopeDevice:
		return rbac.Site(t.OrgID, t.SiteID)
	}
	return rbac.Resource{}
}

func settingErr(code, field, msg string) error {
	return &apperr.Error{Kind: apperr.KindInvalid, Code: code, Message: "Some fields need attention.", Fields: map[string]string{field: msg}}
}

// Resolve finds the target of a request. The caller must be able to see it:
// one they cannot is not found, and a device without the EasyRMM agent has
// nothing to receive a setting (400 setting_scope).
func (s *Service) Resolve(ctx context.Context, c access.Caller, scope Scope, id uuid.UUID) (Target, error) {
	t := Target{Scope: scope}
	var err error
	switch scope {
	case ScopePlatform:
		if !c.CanAnywhere(rbac.PermSiteView) {
			return t, apperr.Forbidden()
		}
		return t, nil
	case ScopeOrganization:
		t.OrgID = id
		err = s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT name FROM organizations WHERE id = $1`, id).Scan(&t.Name)
		})
	case ScopeSite:
		t.SiteID = id
		err = s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT organization_id, name FROM sites WHERE id = $1`, id).Scan(&t.OrgID, &t.Name)
		})
	case ScopeDevice:
		t.DeviceID = id
		var enrolled bool
		err = s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT organization_id, site_id, name, agent_public_key IS NOT NULL FROM devices WHERE id = $1`, id).
				Scan(&t.OrgID, &t.SiteID, &t.Name, &enrolled)
		})
		if err == nil && !enrolled {
			return t, settingErr("setting_scope", "device", "This device has no EasyRMM agent, so it has nothing to receive a setting.")
		}
	default:
		return t, apperr.NotFound()
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return t, apperr.NotFound()
	}
	if err != nil {
		return t, err
	}
	if !c.Can(viewPermission(scope), t.resource()) {
		return t, apperr.NotFound()
	}
	return t, nil
}

func viewPermission(s Scope) rbac.Permission {
	switch s {
	case ScopeOrganization:
		return rbac.PermOrgView
	case ScopeSite:
		return rbac.PermSiteView
	}
	return rbac.PermDeviceView
}

// chainRows returns the setting rows of the target's chain: the platform's,
// and those of the organization, site and device the target has.
func chainRows(ctx context.Context, tx pgx.Tx, key string, t Target) ([]Row, error) {
	rs, err := tx.Query(ctx, `SELECT s.scope, coalesce(s.device_id, s.site_id, s.organization_id, '00000000-0000-0000-0000-000000000000'::uuid),
			coalesce(d.name, st.name, o.name, ''), s.value, s.enforced, s.set_by_label, s.updated_at
		FROM agent_settings s
		LEFT JOIN organizations o ON s.scope = 'organization' AND o.id = s.organization_id
		LEFT JOIN sites st ON s.scope = 'site' AND st.id = s.site_id
		LEFT JOIN devices d ON s.scope = 'device' AND d.id = s.device_id
		WHERE s.key = $1 AND (s.scope = 'platform'
			OR (s.scope = 'organization' AND s.organization_id = $2)
			OR (s.scope = 'site' AND s.site_id = $3)
			OR (s.scope = 'device' AND s.device_id = $4))`,
		key, t.OrgID, t.SiteID, t.DeviceID)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []Row
	for rs.Next() {
		var r Row
		if err := rs.Scan(&r.Scope, &r.ID, &r.Name, &r.Value, &r.Enforced, &r.SetBy, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rs.Err()
}

// atOrAbove keeps the rows of the target's scope and the ones above it.
func atOrAbove(rows []Row, s Scope) []Row {
	var out []Row
	for _, r := range rows {
		if r.Scope.rank() <= s.rank() {
			out = append(out, r)
		}
	}
	return out
}

// SetValue is a value set at the target's own scope.
type SetValue struct {
	Value     json.RawMessage `json:"value"`
	Enforced  bool            `json:"enforced"`
	SetBy     string          `json:"setBy"`
	UpdatedAt time.Time       `json:"updatedAt"`
	// InEffect is false when a higher scope enforces the key: the value is
	// kept, and applies again when the enforcement is lifted.
	InEffect bool `json:"inEffect"`
}

// Inherited is what applies from the scopes above the target's.
type Inherited struct {
	Value json.RawMessage `json:"value"`
	From  *Source         `json:"from"`
}

// Entry is one key as the target sees it.
type Entry struct {
	Key         string          `json:"key"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Type        string          `json:"type"`
	Min         int             `json:"min"`
	Max         int             `json:"max"`
	Default     json.RawMessage `json:"default"`
	Set         *SetValue       `json:"set"`
	Inherited   Inherited       `json:"inherited"`
	EnforcedBy  *Source         `json:"enforcedBy"`
	Effective   Effective       `json:"effective"`
	CanWrite    bool            `json:"canWrite"`
	CanEnforce  bool            `json:"canEnforce"`
	Permission  string          `json:"permission"`
}

// Listing is every key at a target.
type Listing struct {
	Scope  Scope   `json:"scope"`
	ID     string  `json:"id,omitempty"`
	Name   string  `json:"name,omitempty"`
	Limits Limits  `json:"limits"`
	Items  []Entry `json:"items"`
	// Device is set for a device: what the server knows of its agent's
	// interval.
	Device *DeviceState `json:"device,omitempty"`
}

// DeviceState is what the server keeps of a device's interval and
// liveness.
type DeviceState struct {
	HeartbeatSeconds int        `json:"heartbeatSeconds"`
	OnlineUntil      *time.Time `json:"onlineUntil"`
}

// List returns every key at the target: the value set there, what is
// inherited and from where, whether a higher scope enforces it, what is in
// effect, and whether the caller may write it.
func (s *Service) List(ctx context.Context, c access.Caller, t Target) (Listing, error) {
	out := Listing{Scope: t.Scope, Name: t.Name}
	if id := t.id(); id != uuid.Nil {
		out.ID = id.String()
	}
	allowed := t.Scope == ScopePlatform || devscope.Allowed(t.OrgID)
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var err error
		if out.Limits, err = readLimits(ctx, tx); err != nil {
			return err
		}
		for _, k := range catalog {
			rows, err := chainRows(ctx, tx, k.Name, t)
			if err != nil {
				return err
			}
			out.Items = append(out.Items, s.entry(c, t, k, rows, out.Limits, allowed))
		}
		if t.Scope == ScopeDevice {
			var d DeviceState
			if err := tx.QueryRow(ctx, `SELECT agent_heartbeat_seconds, agent_online_until FROM devices WHERE id = $1`, t.DeviceID).
				Scan(&d.HeartbeatSeconds, &d.OnlineUntil); err != nil {
				return err
			}
			out.Device = &d
		}
		return nil
	})
	return out, err
}

func (s *Service) entry(c access.Caller, t Target, k Key, rows []Row, l Limits, allowed bool) Entry {
	rows = atOrAbove(rows, t.Scope)
	e := Entry{
		Key: k.Name, Title: k.Title, Description: k.Line, Type: "integer", Min: k.Lowest(l), Max: k.Max,
		Default:    json.RawMessage(itoa(max(k.Default, k.Lowest(l)))),
		Permission: string(k.Permission(t.Scope)),
	}
	var own *Row
	for i := range rows {
		if rows[i].Scope == t.Scope {
			own = &rows[i]
		}
	}
	higher := above(rows, t.Scope)
	if enf := Enforcer(higher); enf != nil {
		e.EnforcedBy = enf.source()
	}
	inh := k.Resolve(higher, l)
	e.Inherited = Inherited{Value: inh.Value, From: inh.From}
	e.Effective = k.Resolve(rows, l)
	if own != nil {
		e.Set = &SetValue{Value: own.Value, Enforced: own.Enforced, SetBy: own.SetBy, UpdatedAt: own.UpdatedAt, InEffect: e.EnforcedBy == nil}
	}
	e.CanWrite = allowed && k.CanSetAt(t.Scope) && e.EnforcedBy == nil && s.mayWrite(c, t, k)
	e.CanEnforce = e.CanWrite && k.CanEnforceAt(t.Scope)
	return e
}

func (s *Service) mayWrite(c access.Caller, t Target, k Key) bool {
	perm := k.Permission(t.Scope)
	if t.Scope == ScopePlatform {
		return c.CanGlobal(perm)
	}
	return c.Can(perm, t.resource())
}

// PutInput is a value to set.
type PutInput struct {
	Value    json.RawMessage `json:"value"`
	Enforced bool            `json:"enforced"`
}

// allowWrite counts a write against the caller's and the target's limits
// (429 rate_limited beyond them).
func (s *Service) allowWrite(c access.Caller, target string) error {
	who := c.Actor.ID.String()
	if !s.byCaller.Allow(who) {
		return apperr.TooMany("rate_limited", "Too many settings changes. Try again in a few seconds.", time.Second)
	}
	if !s.byTarget.Allow(target) {
		return apperr.TooMany("rate_limited", "This target's settings were changed too often. Try again in a few seconds.", 2*time.Second)
	}
	return nil
}

func (t Target) limiterKey() string { return string(t.Scope) + ":" + t.id().String() }

// guard is everything a write needs before it touches the database.
func (s *Service) guard(c access.Caller, t Target, k Key) error {
	if !k.CanSetAt(t.Scope) {
		return settingErr("setting_scope", "scope", "This setting cannot be set at that level.")
	}
	if !s.mayWrite(c, t, k) {
		return apperr.Forbidden()
	}
	// The development scope holds back every organization but one from new
	// behavior: nothing is written for the others.
	if t.Scope != ScopePlatform && !devscope.Allowed(t.OrgID) {
		return apperr.Forbidden()
	}
	return s.allowWrite(c, t.limiterKey())
}

func enforcedErr() error {
	return apperr.Conflict("setting_enforced", "This setting is enforced above, so nothing can be set here. The value kept applies again when the enforcement is lifted.")
}

// Put sets a key at the target, or changes what is set.
func (s *Service) Put(ctx context.Context, c access.Caller, t Target, name string, in PutInput) (Entry, error) {
	k, ok := Lookup(name)
	if !ok {
		return Entry{}, apperr.NotFound()
	}
	if in.Enforced && !k.CanEnforceAt(t.Scope) {
		return Entry{}, settingErr("setting_scope", "enforced", "This setting cannot be enforced at that level.")
	}
	if err := s.guard(c, t, k); err != nil {
		return Entry{}, err
	}
	var e Entry
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		l, err := readLimits(ctx, tx)
		if err != nil {
			return err
		}
		value, err := k.Check(in.Value, l)
		if err != nil {
			return settingErr("setting_invalid", "value", err.Error())
		}
		rows, err := chainRows(ctx, tx, k.Name, t)
		if err != nil {
			return err
		}
		if Enforcer(above(rows, t.Scope)) != nil {
			return enforcedErr()
		}
		var old json.RawMessage
		var oldEnforced bool
		for _, r := range rows {
			if r.Scope == t.Scope {
				old, oldEnforced = r.Value, r.Enforced
			}
		}
		var by any
		if c.Principal != nil {
			by = c.Principal.UserID
		}
		var orgArg, siteArg, devArg any
		if t.Scope != ScopePlatform {
			orgArg = t.OrgID
		}
		if t.Scope == ScopeSite || t.Scope == ScopeDevice {
			siteArg = t.SiteID
		}
		if t.Scope == ScopeDevice {
			devArg = t.DeviceID
		}
		tag, err := tx.Exec(ctx, `INSERT INTO agent_settings (key, scope, organization_id, site_id, device_id, value, enforced, set_by, set_by_label)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (`+conflictTarget(t.Scope)+`) WHERE scope = '`+string(t.Scope)+`'
			DO UPDATE SET value = EXCLUDED.value, enforced = EXCLUDED.enforced, set_by = EXCLUDED.set_by,
				set_by_label = EXCLUDED.set_by_label, updated_at = now()`,
			k.Name, string(t.Scope), orgArg, siteArg, devArg, []byte(value), in.Enforced, by, c.Actor.Label)
		if err != nil {
			return mapWriteError(err)
		}
		if tag.RowsAffected() == 0 {
			return apperr.Forbidden()
		}
		details := map[string]any{"key": k.Name, "scope": string(t.Scope), "target": t.Name, "new": value, "enforced": in.Enforced}
		if old != nil {
			details["old"], details["oldEnforced"] = old, oldEnforced
		}
		return s.audit.Write(ctx, tx, s.event(c, t, ActionSet, details))
	})
	if err != nil {
		return e, err
	}
	return s.one(ctx, c, t, k)
}

func conflictTarget(s Scope) string {
	switch s {
	case ScopePlatform:
		return "key"
	case ScopeOrganization:
		return "organization_id, key"
	case ScopeSite:
		return "site_id, key"
	}
	return "device_id, key"
}

// mapWriteError turns what row-level security and the device check say into
// the errors the API has.
func mapWriteError(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		switch pg.Code {
		case "42501":
			return apperr.Forbidden()
		case "23514":
			if pg.ConstraintName == "agent_settings_device_agent" {
				return settingErr("setting_scope", "device", "This device has no EasyRMM agent, so it has nothing to receive a setting.")
			}
		}
	}
	return err
}

func (s *Service) event(c access.Caller, t Target, action string, details map[string]any) audit.Event {
	return audit.Event{
		Actor: c.Actor, Action: action, Outcome: audit.Success,
		OrganizationID: t.OrgID, SiteID: t.SiteID, DeviceID: t.DeviceID,
		TargetType: "agent_setting", TargetID: t.limiterKey(), Details: details,
	}
}

// one lists the key just written.
func (s *Service) one(ctx context.Context, c access.Caller, t Target, k Key) (Entry, error) {
	l, err := s.List(ctx, c, t)
	if err != nil {
		return Entry{}, err
	}
	for _, e := range l.Items {
		if e.Key == k.Name {
			return e, nil
		}
	}
	return Entry{}, apperr.NotFound()
}

// Delete goes back to inheriting. Clearing a value is allowed under an
// enforcement too: it only takes away what was kept.
func (s *Service) Delete(ctx context.Context, c access.Caller, t Target, name string) error {
	k, ok := Lookup(name)
	if !ok {
		return apperr.NotFound()
	}
	if err := s.guard(c, t, k); err != nil {
		return err
	}
	return s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var old json.RawMessage
		var oldEnforced bool
		err := tx.QueryRow(ctx, `DELETE FROM agent_settings WHERE key = $1 AND scope = $2
			AND organization_id IS NOT DISTINCT FROM $3 AND site_id IS NOT DISTINCT FROM $4 AND device_id IS NOT DISTINCT FROM $5
			RETURNING value, enforced`,
			k.Name, string(t.Scope), nilIf(t.Scope != ScopePlatform, t.OrgID),
			nilIf(t.Scope == ScopeSite || t.Scope == ScopeDevice, t.SiteID), nilIf(t.Scope == ScopeDevice, t.DeviceID)).Scan(&old, &oldEnforced)
		if errors.Is(err, pgx.ErrNoRows) {
			return apperr.NotFound()
		}
		if err != nil {
			return mapWriteError(err)
		}
		return s.audit.Write(ctx, tx, s.event(c, t, ActionCleared, map[string]any{
			"key": k.Name, "scope": string(t.Scope), "target": t.Name, "old": old, "oldEnforced": oldEnforced}))
	})
}

func nilIf(cond bool, id uuid.UUID) any {
	if !cond {
		return nil
	}
	return id
}

// CatalogEntry is a key with the permission it needs at each scope, for
// the console's editors.
type CatalogEntry struct {
	Key         string           `json:"key"`
	Title       string           `json:"title"`
	Description string           `json:"description"`
	Type        string           `json:"type"`
	Min         int              `json:"min"`
	Max         int              `json:"max"`
	Default     int              `json:"default"`
	SetAt       []Scope          `json:"setAt"`
	EnforceAt   []Scope          `json:"enforceAt"`
	Permissions map[Scope]string `json:"permissions"`
}

// Keys describes the catalog.
func Keys() []CatalogEntry {
	var out []CatalogEntry
	for _, k := range catalog {
		e := CatalogEntry{Key: k.Name, Title: k.Title, Description: k.Line, Type: "integer", Min: k.Min, Max: k.Max, Default: k.Default,
			SetAt: k.SetAt, EnforceAt: k.EnforceAt, Permissions: map[Scope]string{}}
		for _, s := range k.SetAt {
			e.Permissions[s] = string(k.Permission(s))
		}
		out = append(out, e)
	}
	return out
}

// EffectiveHeartbeat is the interval a device's agent is answered with, in
// seconds: the effective value of the key, after the platform's minimum.
// Organizations outside the development scope keep today's 60 seconds. It
// runs inside the heartbeat's own transaction: one indexed query over at
// most four rows, and the platform's limits.
func EffectiveHeartbeat(ctx context.Context, tx pgx.Tx, org, site, device uuid.UUID) (int, error) {
	if !devscope.Allowed(org) {
		return DefaultHeartbeatSeconds, nil
	}
	k := catalog[0]
	l, err := readLimits(ctx, tx)
	if err != nil {
		return 0, err
	}
	rows, err := chainRows(ctx, tx, k.Name, Target{Scope: ScopeDevice, OrgID: org, SiteID: site, DeviceID: device})
	if err != nil {
		return 0, err
	}
	return k.Resolve(rows, l).Int(), nil
}
