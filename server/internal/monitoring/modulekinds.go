package monitoring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
)

// Windows module alerts (ADR-0073 section 6). A module registers its alert
// kinds and default policies; the evaluator reads each kind's value from the
// snapshot of its action (windows_module_snapshots) in the same one-minute
// pass as the other kinds, through the module gate.

// ErrUnknown is what a kind's Eval returns when the snapshot does not say:
// nothing changes, an open alert stays as it is.
var ErrUnknown = errors.New("monitoring: the snapshot does not tell")

// Verdict is a kind's judgement of one snapshot.
type Verdict struct {
	// Holds says the alert's condition holds.
	Holds bool
	// NotApplicable says the kind does not apply on this computer (Defender
	// in passive mode, say): an open alert resolves with that reason.
	NotApplicable bool
	// Value is recorded with the alert; Detail says in words why it holds.
	Value  float64
	Detail string
}

// ThresholdSpec says what a kind's threshold is.
type ThresholdSpec struct {
	// Used says the policy has a threshold, Min and Max bound it, and Unit
	// names it for people ("days").
	Used     bool
	Min, Max int
	Unit     string
}

// ModuleKind is an alert kind a module supplies.
type ModuleKind struct {
	// Name is the kind, "<module>_<what>".
	Name   string
	Label  string
	Module modules.Module
	// Action is the snapshot action the value comes from.
	Action    string
	Threshold ThresholdSpec
	// Grace says the policy's minutes are a grace period: the condition
	// must have held, on readings, for that long before the alert opens.
	// Without it the minutes are unused.
	Grace bool
	// LowestWins says the smaller threshold is the more urgent (days left
	// before an expiry), so of several policies that hold, the lowest opens.
	LowestWins bool
	// MaxAge is how old the snapshot may be to be judged; older ones change
	// nothing. Zero means DefaultMaxAge.
	MaxAge time.Duration
	// Eval judges the snapshot's data with the policy's threshold.
	Eval func(data json.RawMessage, threshold *int) (Verdict, error)
}

// DefaultMaxAge is how old a snapshot may be and still be judged.
const DefaultMaxAge = 3 * time.Hour

// DefaultPolicy is a policy a module asks the server to create for every
// organization, once, when the module is first enabled there.
type DefaultPolicy struct {
	// Key identifies it for the module, never changes, and makes creation
	// idempotent.
	Key         string
	Name        string
	Description string
	Kind        string
	Threshold   *int
	Minutes     int
	Severity    string
	// Enabled is whether it starts on.
	Enabled bool
}

// ModuleAlerts is everything a module supplies to monitoring.
type ModuleAlerts struct {
	Module   modules.Module
	Kinds    []ModuleKind
	Defaults []DefaultPolicy
}

var kindName = regexp.MustCompile(`^[a-z][a-z0-9_]{1,39}$`)

var registry = struct {
	sync.RWMutex
	kinds    map[string]ModuleKind
	defaults map[modules.Module][]DefaultPolicy
}{kinds: map[string]ModuleKind{}, defaults: map[modules.Module][]DefaultPolicy{}}

// RegisterModuleAlerts adds a module's kinds and default policies. It is
// called while wiring, before the server serves (again for a module, it
// replaces that module's), and returns an error for a
// kind that is badly named, already registered, built in, or whose default
// does not validate.
func RegisterModuleAlerts(m ModuleAlerts) error {
	registry.Lock()
	defer registry.Unlock()
	if _, ok := modules.Lookup(m.Module); !ok {
		return fmt.Errorf("monitoring: %q is not a module", m.Module)
	}
	local := map[string]ModuleKind{}
	for _, k := range m.Kinds {
		// Registering a module again replaces its kinds (a second app in one
		// process, as in tests); another module's name is a clash.
		other, dup := registry.kinds[k.Name]
		dup = dup && other.Module != m.Module
		switch {
		case !kindName.MatchString(k.Name) || validBuiltin(k.Name) || k.Name == KindRepairFailed:
			return fmt.Errorf("monitoring: %q is not a valid module alert kind", k.Name)
		case dup || local[k.Name].Name != "":
			return fmt.Errorf("monitoring: alert kind %q is registered twice", k.Name)
		case k.Module != m.Module || k.Label == "" || k.Action == "" || k.Eval == nil:
			return fmt.Errorf("monitoring: alert kind %q is incomplete", k.Name)
		case k.Threshold.Used && (k.Threshold.Min < 1 || k.Threshold.Max < k.Threshold.Min || k.Threshold.Max > 100):
			return fmt.Errorf("monitoring: alert kind %q has a bad threshold range", k.Name)
		}
		local[k.Name] = k
	}
	keys := map[string]bool{}
	for _, d := range m.Defaults {
		k, ok := local[d.Kind]
		cd := condition{name: d.Name, description: d.Description, kind: d.Kind, severity: d.Severity, threshold: d.Threshold, minutes: d.Minutes, enabled: d.Enabled}
		switch {
		case !ok || d.Key == "" || len(d.Key) > 100 || keys[d.Key] || d.Name == "" || len(d.Name) > MaxName ||
			(d.Severity != SeverityWarning && d.Severity != SeverityCritical) || (!k.Threshold.Used && d.Threshold != nil):
			return fmt.Errorf("monitoring: default policy %q is not valid", d.Key)
		case cd.validateModule(k) != nil:
			return fmt.Errorf("monitoring: default policy %q does not validate", d.Key)
		}
		keys[d.Key] = true
	}
	for n, k := range registry.kinds {
		if k.Module == m.Module {
			delete(registry.kinds, n)
		}
	}
	for n, k := range local {
		registry.kinds[n] = k
	}
	registry.defaults[m.Module] = slices.Clone(m.Defaults)
	return nil
}

func validBuiltin(k string) bool {
	return k == KindOffline || k == KindCPU || k == KindMemory || k == KindDisk || k == KindDiskHealth ||
		k == KindRemoteDown || k == KindAgentSilent
}

// ModuleKindOf returns a registered module kind.
func ModuleKindOf(name string) (ModuleKind, bool) {
	registry.RLock()
	defer registry.RUnlock()
	k, ok := registry.kinds[name]
	return k, ok
}

// ModuleKinds lists the registered kinds by name.
func ModuleKinds() []ModuleKind {
	registry.RLock()
	defer registry.RUnlock()
	out := make([]ModuleKind, 0, len(registry.kinds))
	for _, k := range registry.kinds {
		out = append(out, k)
	}
	slices.SortFunc(out, func(a, b ModuleKind) int { return compareStrings(a.Name, b.Name) })
	return out
}

func compareStrings(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func defaultsOf(m modules.Module) []DefaultPolicy {
	registry.RLock()
	defer registry.RUnlock()
	return slices.Clone(registry.defaults[m])
}

// validateModule checks a module kind's policy: no disk check, the threshold
// the kind takes, and minutes that are the grace period or unused.
func (cd *condition) validateModule(k ModuleKind) error {
	cd.checkName = nil
	f := apperr.Fields{}
	if k.Threshold.Used {
		f.Check(cd.threshold != nil && *cd.threshold >= k.Threshold.Min && *cd.threshold <= k.Threshold.Max, "threshold",
			fmt.Sprintf("Use %d to %d %s.", k.Threshold.Min, k.Threshold.Max, k.Threshold.Unit))
	} else {
		cd.threshold = nil
	}
	if k.Grace {
		f.Check(cd.minutes >= 1 && cd.minutes <= MaxMinutes, "minutes", "Use 1 to 1,440 minutes.")
	} else {
		cd.minutes = 1
	}
	return f.Err()
}

// ModuleGate is modules.Service.Allowed: the module's toggle for the site
// and devscope.Allowed for the organization.
type ModuleGate interface {
	Allowed(ctx context.Context, org, site uuid.UUID, m modules.Module) bool
}

// UseModules lets the evaluator judge Windows module kinds, asking g before
// every judgement and every default policy. Without it they judge nothing.
// Call it before Run.
func (s *Service) UseModules(g ModuleGate) { s.modGate = g }

// EnsureDefaults creates a module's default policies for an organization,
// once: policies already there (by module and key) are left as they are,
// whatever an administrator did to them. It is a no-op outside the
// development scope.
func EnsureDefaults(ctx context.Context, tx pgx.Tx, org uuid.UUID, m modules.Module) error {
	if !devscope.Allowed(org) {
		return nil
	}
	for _, d := range defaultsOf(m) {
		// Minutes a kind does not use are stored as 1, as for a policy made
		// through the API.
		cd := condition{threshold: d.Threshold, minutes: d.Minutes}
		if k, ok := ModuleKindOf(d.Kind); ok {
			_ = cd.validateModule(k)
		}
		d.Minutes = cd.minutes
		// A user's policy that already has the name keeps it; the default is
		// then skipped, not renamed.
		if _, err := tx.Exec(ctx, `INSERT INTO alert_policies (organization_id, name, description, kind, threshold, minutes, severity, enabled, module, default_key)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT DO NOTHING`,
			org, d.Name, d.Description, d.Kind, d.Threshold, d.Minutes, d.Severity, d.Enabled, string(m), d.Key); err != nil {
			return fmt.Errorf("monitoring: creating default policy %q: %w", d.Key, err)
		}
	}
	return nil
}

// moduleRow is what one enabled policy sees on one device it covers.
type moduleRow struct {
	policyID, deviceID, org, site uuid.UUID
	threshold                     *int
	minutes                       int
	alertID                       *uuid.UUID
	data                          []byte
	taken                         *time.Time
	since                         *time.Time
	rolesKnown, rolePresent       bool
}

type moduleBatch struct {
	policies, devices []uuid.UUID
	values            []float64
	details           []string
	reasons           []string
	times             []time.Time
}

func (b *moduleBatch) add(policy, device uuid.UUID, value float64, detail, reason string, t time.Time) {
	b.policies = append(b.policies, policy)
	b.devices = append(b.devices, device)
	b.values = append(b.values, value)
	b.details = append(b.details, detail)
	b.reasons = append(b.reasons, reason)
	b.times = append(b.times, t)
}

// evaluateModules creates default policies where a module is on and a
// computer has its role, then opens, updates and resolves the alerts of every
// registered kind from its snapshot. A module that is off, or an organization
// outside the development scope, is judged not at all and its open alerts
// resolve with "module_off"; a role that is gone resolves them with
// "role_removed"; a kind that does not apply resolves with "not_applicable".
func (s *Service) evaluateModules(ctx context.Context, tx pgx.Tx, now time.Time) (opened, resolved int, err error) {
	if s.modGate == nil {
		return 0, 0, nil
	}
	allowed := map[[3]uuid.UUID]bool{}
	allow := func(org, site uuid.UUID, m modules.Module) bool {
		k := [3]uuid.UUID{org, site, uuid.NewSHA1(uuid.Nil, []byte(m))}
		v, ok := allowed[k]
		if !ok {
			v = s.modGate.Allowed(ctx, org, site, m)
			allowed[k] = v
		}
		return v
	}
	if err := s.ensureModuleDefaults(ctx, tx, allow); err != nil {
		return 0, 0, err
	}
	for _, k := range ModuleKinds() {
		o, r, err := s.evaluateKind(ctx, tx, now, k, allow)
		opened += o
		resolved += r
		if err != nil {
			return opened, resolved, fmt.Errorf("monitoring: evaluating %s: %w", k.Name, err)
		}
	}
	return opened, resolved, nil
}

// ensureModuleDefaults creates the defaults of every module for each
// organization that has a computer with the module's role and none yet.
func (s *Service) ensureModuleDefaults(ctx context.Context, tx pgx.Tx, allow func(org, site uuid.UUID, m modules.Module) bool) error {
	registry.RLock()
	var mods []modules.Module
	for m, list := range registry.defaults {
		if len(list) > 0 {
			mods = append(mods, m)
		}
	}
	registry.RUnlock()
	for _, m := range mods {
		def, ok := modules.Lookup(m)
		if !ok {
			continue
		}
		first := defaultsOf(m)[0].Key
		rows, err := tx.Query(ctx, `SELECT DISTINCT d.organization_id FROM devices d
			WHERE d.platform = 'windows' AND d.agent_public_key IS NOT NULL
			  AND jsonb_path_exists(coalesce(d.roles, '[]'::jsonb), '$[*] ? (@.name == $role)', jsonb_build_object('role', $1::text))
			  AND NOT EXISTS (SELECT 1 FROM alert_policies p WHERE p.organization_id = d.organization_id AND p.module = $2 AND p.default_key = $3)`,
			def.Role, string(m), first)
		if err != nil {
			return err
		}
		var orgs []uuid.UUID
		for rows.Next() {
			var o uuid.UUID
			if err := rows.Scan(&o); err != nil {
				rows.Close()
				return err
			}
			orgs = append(orgs, o)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, o := range orgs {
			if allow(o, uuid.Nil, m) {
				if err := EnsureDefaults(ctx, tx, o, m); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (s *Service) evaluateKind(ctx context.Context, tx pgx.Tx, now time.Time, k ModuleKind, allow func(org, site uuid.UUID, m modules.Module) bool) (opened, resolved int, err error) {
	def, _ := modules.Lookup(k.Module)
	rs, err := tx.Query(ctx, `SELECT p.id, d.id, d.organization_id, d.site_id, p.threshold, p.minutes, a.id, s.data, s.taken_at, c.since,
			d.roles IS NOT NULL,
			jsonb_path_exists(coalesce(d.roles, '[]'::jsonb), '$[*] ? (@.name == $role)', jsonb_build_object('role', $3::text))
		FROM alert_policies p
		JOIN devices d ON d.platform = 'windows' AND d.agent_public_key IS NOT NULL
			AND (p.organization_id IS NULL OR (p.organization_id = d.organization_id AND (p.site_id IS NULL OR p.site_id = d.site_id)))
		LEFT JOIN alerts a ON a.policy_id = p.id AND a.device_id = d.id AND a.status <> 'resolved'
		LEFT JOIN windows_module_snapshots s ON s.device_id = d.id AND s.action = $2 AND s.params_hash = ''
		LEFT JOIN windows_module_conditions c ON c.policy_id = p.id AND c.device_id = d.id
		WHERE p.enabled AND p.kind = $1 AND (a.id IS NOT NULL OR s.device_id IS NOT NULL)`,
		k.Name, k.Action, def.Role)
	if err != nil {
		return 0, 0, err
	}
	var list []moduleRow
	for rs.Next() {
		var r moduleRow
		if err := rs.Scan(&r.policyID, &r.deviceID, &r.org, &r.site, &r.threshold, &r.minutes, &r.alertID, &r.data, &r.taken, &r.since,
			&r.rolesKnown, &r.rolePresent); err != nil {
			rs.Close()
			return 0, 0, err
		}
		list = append(list, r)
	}
	rs.Close()
	if err := rs.Err(); err != nil {
		return 0, 0, err
	}
	maxAge := k.MaxAge
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	type judged struct {
		row   moduleRow
		v     Verdict
		ready bool
	}
	var (
		opens, updates, resolves, starts, ends moduleBatch
		holding                                []judged
		best                                   = map[uuid.UUID]int{}
	)
	for _, r := range list {
		hasAlert := r.alertID != nil
		resolve := func(reason string) {
			if hasAlert {
				resolves.add(*r.alertID, r.deviceID, 0, "", reason, now)
			}
			if r.since != nil {
				ends.add(r.policyID, r.deviceID, 0, "", "", now)
			}
		}
		switch {
		case !allow(r.org, r.site, k.Module):
			resolve("module_off")
			continue
		case r.rolesKnown && !r.rolePresent:
			resolve("role_removed")
			continue
		case r.data == nil || r.taken == nil || now.Sub(*r.taken) > maxAge:
			continue
		}
		v, err := k.Eval(r.data, r.threshold)
		switch {
		case err != nil:
			continue
		case v.NotApplicable:
			resolve("not_applicable")
		case !v.Holds:
			resolve("cleared")
		default:
			holding = append(holding, judged{row: r, v: v, ready: true})
		}
	}
	for i := range holding {
		r := holding[i].row
		if k.Grace {
			since := *r.taken
			if r.since != nil {
				since = *r.since
			} else {
				starts.add(r.policyID, r.deviceID, 0, "", "", since)
			}
			holding[i].ready = now.Sub(since) >= time.Duration(r.minutes)*time.Minute
		}
		if holding[i].ready && r.threshold != nil {
			switch cur, seen := best[r.deviceID]; {
			case k.LowestWins && (!seen || *r.threshold < cur):
				best[r.deviceID] = *r.threshold
			case !k.LowestWins:
				best[r.deviceID] = max(cur, *r.threshold)
			}
		}
	}
	for _, j := range holding {
		r, v := j.row, j.v
		if !j.ready {
			continue
		}
		if r.alertID != nil {
			updates.add(*r.alertID, r.deviceID, v.Value, v.Detail, "", now)
			continue
		}
		// The best match: of several policies that hold on one computer,
		// only the one with the highest threshold opens an alert (the lowest,
		// for a kind whose smaller threshold is the more urgent).
		if r.threshold != nil && ((!k.LowestWins && *r.threshold < best[r.deviceID]) || (k.LowestWins && *r.threshold > best[r.deviceID])) {
			continue
		}
		opens.add(r.policyID, r.deviceID, v.Value, v.Detail, "", now)
	}
	if len(starts.policies) > 0 {
		if _, err := tx.Exec(ctx, `INSERT INTO windows_module_conditions (policy_id, device_id, since)
			SELECT * FROM unnest($1::uuid[], $2::uuid[], $3::timestamptz[]) ON CONFLICT DO NOTHING`,
			starts.policies, starts.devices, starts.times); err != nil {
			return 0, 0, err
		}
	}
	if len(ends.policies) > 0 {
		if _, err := tx.Exec(ctx, `DELETE FROM windows_module_conditions c USING unnest($1::uuid[], $2::uuid[]) AS x(policy_id, device_id)
			WHERE c.policy_id = x.policy_id AND c.device_id = x.device_id`, ends.policies, ends.devices); err != nil {
			return 0, 0, err
		}
	}
	if len(opens.policies) > 0 {
		tag, err := tx.Exec(ctx, `INSERT INTO alerts (policy_id, device_id, name, kind, threshold, minutes, severity, detail, value, last_value, opened_at)
			SELECT p.id, x.device_id, p.name, p.kind, p.threshold, p.minutes, p.severity, left(x.detail, 500), x.value, x.value, $5
			FROM unnest($1::uuid[], $2::uuid[], $3::text[], $4::float8[]) AS x(policy_id, device_id, detail, value)
			JOIN alert_policies p ON p.id = x.policy_id
			ON CONFLICT (policy_id, device_id, subject) WHERE status <> 'resolved' DO NOTHING`,
			opens.policies, opens.devices, opens.details, opens.values, now)
		if err != nil {
			return 0, 0, err
		}
		opened = int(tag.RowsAffected())
	}
	if len(updates.policies) > 0 {
		if _, err := tx.Exec(ctx, `UPDATE alerts a SET last_value = x.value, detail = left(x.detail, 500)
			FROM unnest($1::uuid[], $2::float8[], $3::text[]) AS x(id, value, detail)
			WHERE a.id = x.id AND a.status <> 'resolved' AND (a.last_value <> x.value OR a.detail <> left(x.detail, 500))`,
			updates.policies, updates.values, updates.details); err != nil {
			return 0, 0, err
		}
	}
	if len(resolves.policies) > 0 {
		tag, err := tx.Exec(ctx, `UPDATE alerts a SET status = 'resolved', resolved_at = $3, resolution = x.reason
			FROM unnest($1::uuid[], $2::text[]) AS x(id, reason)
			WHERE a.id = x.id AND a.status <> 'resolved'`, resolves.policies, resolves.reasons, now)
		if err != nil {
			return 0, 0, err
		}
		resolved = int(tag.RowsAffected())
	}
	return opened, resolved, nil
}

// ResolveModuleAlerts resolves a device's open alerts of a module's kinds
// with a reason; the role-removal hook uses it in the heartbeat's
// transaction (ADR-0073 section 1).
func ResolveModuleAlerts(ctx context.Context, tx pgx.Tx, deviceID uuid.UUID, m modules.Module, reason string, now time.Time) error {
	var names []string
	for _, k := range ModuleKinds() {
		if k.Module == m {
			names = append(names, k.Name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `UPDATE alerts SET status = 'resolved', resolved_at = $3, resolution = $4
		WHERE device_id = $1 AND kind = ANY ($2) AND status <> 'resolved'`, deviceID, names, now, reason); err != nil {
		return fmt.Errorf("monitoring: resolving %s alerts: %w", m, err)
	}
	_, err := tx.Exec(ctx, `DELETE FROM windows_module_conditions c USING alert_policies p
		WHERE c.device_id = $1 AND p.id = c.policy_id AND p.kind = ANY ($2)`, deviceID, names)
	return err
}

// RoleRemovedHook is the modules framework's hook for a role that went away:
// the module's open alerts on the device resolve with "role_removed".
func RoleRemovedHook(ctx context.Context, tx pgx.Tx, deviceID, _ uuid.UUID, m modules.Module) error {
	return ResolveModuleAlerts(ctx, tx, deviceID, m, "role_removed", time.Now())
}
