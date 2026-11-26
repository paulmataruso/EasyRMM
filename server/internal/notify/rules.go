package notify

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// Rule sources, and the dimensions' modes (ADR-0053, "Device alert rules").
const (
	SourceAlerts  = "alerts"
	SourceNotices = "notices"

	ModeAny  = "any"
	ModeList = "list"

	// ConditionAgentRemoved is the condition of the notice raised when an
	// agent was removed without a request (slice 7 raises it).
	ConditionAgentRemoved = "agent_removed"

	MaxRuleChannels = 20
)

// Audit actions of rules.
const (
	ActionRuleCreate = "notification_rule.create"
	ActionRuleUpdate = "notification_rule.update"
	ActionRuleDelete = "notification_rule.delete"
)

// ErrRuleQuota is an organization at its quota of rules.
var ErrRuleQuota = apperr.Conflict("rule_quota", "This organization has reached its limit of notification rules. Delete one first, or ask a super administrator to raise the limit.")

// ListFilter is a dimension whose values are rows: organizations, sites or
// device groups.
type ListFilter struct {
	Mode string      `json:"mode"`
	IDs  []uuid.UUID `json:"ids"`
}

// ValueFilter is a dimension whose values are words.
type ValueFilter struct {
	Mode   string   `json:"mode"`
	Values []string `json:"values"`
}

// Rule is a rule as the console shows it and sends it.
type Rule struct {
	ID             uuid.UUID   `json:"id"`
	OrganizationID *uuid.UUID  `json:"organizationId"`
	Platform       bool        `json:"platform"`
	Source         string      `json:"source"`
	Name           string      `json:"name"`
	Enabled        bool        `json:"enabled"`
	Organizations  ListFilter  `json:"organizations"`
	Sites          ListFilter  `json:"sites"`
	Groups         ListFilter  `json:"groups"`
	DeviceKinds    ValueFilter `json:"deviceKinds"`
	Severities     ValueFilter `json:"severities"`
	Conditions     ValueFilter `json:"conditions"`
	Checks         ValueFilter `json:"checks"`
	WaitMinutes    int         `json:"waitMinutes"`
	OnResolve      bool        `json:"onResolve"`
	OnAcknowledge  bool        `json:"onAcknowledge"`
	ReminderHours  int         `json:"reminderHours"`
	IgnoreWindows  bool        `json:"ignoreWindows"`
	GroupOutages   bool        `json:"groupOutages"`
	ChannelIDs     []uuid.UUID `json:"channelIds"`
	// MatchesNothing is set when a list was emptied by deletions: the rule
	// stays in list mode and matches nothing.
	MatchesNothing bool      `json:"matchesNothing"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

func (r *Rule) owner() uuid.UUID {
	if r.OrganizationID == nil {
		return uuid.Nil
	}
	return *r.OrganizationID
}

// Subject is what a rule is matched against: an alert's device and
// condition, or a notice.
type Subject struct {
	Source    string
	Org       uuid.UUID
	Site      uuid.UUID
	Group     *uuid.UUID
	Kind      string // the device's kind, "" when unknown
	Severity  string
	Condition string
	Check     string
}

func listHas(f ListFilter, id uuid.UUID) bool { return slices.Contains(f.IDs, id) }

func valueMatches(f ValueFilter, v string) bool {
	if f.Mode != ModeList {
		return true
	}
	return v != "" && slices.Contains(f.Values, v)
}

// Matches reports whether the rule is about the subject. A list emptied by
// deletions matches nothing, never everything.
func (r *Rule) Matches(s Subject) bool {
	if !r.Enabled || r.Source != s.Source {
		return false
	}
	if r.OrganizationID != nil && *r.OrganizationID != s.Org {
		return false
	}
	if r.Organizations.Mode == ModeList && !listHas(r.Organizations, s.Org) {
		return false
	}
	if r.Sites.Mode == ModeList && !listHas(r.Sites, s.Site) {
		return false
	}
	if r.Groups.Mode == ModeList && (s.Group == nil || !listHas(r.Groups, *s.Group)) {
		return false
	}
	if !valueMatches(r.DeviceKinds, s.Kind) || !valueMatches(r.Severities, s.Severity) || !valueMatches(r.Conditions, s.Condition) {
		return false
	}
	if s.Condition == "disk_health" && !valueMatches(r.Checks, s.Check) {
		return false
	}
	return true
}

// DeviceKind is a device's kind: what someone set, else what the agent
// reported, else what its operating system's description says; "" when none
// of them does (ADR-0053).
func DeviceKind(set, reported *string, osDescription, platform string) string {
	for _, p := range []*string{set, reported} {
		if p != nil && (*p == "server" || *p == "workstation") {
			return *p
		}
	}
	switch platform {
	case "windows":
		if strings.Contains(strings.ToLower(osDescription), "windows server") {
			return "server"
		}
		return "workstation"
	case "linux":
		return "server"
	case "macos":
		return "workstation"
	}
	if strings.Contains(strings.ToLower(osDescription), "windows server") {
		return "server"
	}
	return ""
}

var conditionPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{1,62}$`)

func cleanValues(field string, f ValueFilter, allowed []string) (ValueFilter, error) {
	switch f.Mode {
	case "", ModeAny:
		return ValueFilter{Mode: ModeAny, Values: []string{}}, nil
	case ModeList:
	default:
		return f, apperr.Invalid(field, "Choose any or a list.")
	}
	out := ValueFilter{Mode: ModeList, Values: []string{}}
	for _, v := range f.Values {
		v = strings.TrimSpace(v)
		switch {
		case allowed != nil && !slices.Contains(allowed, v):
			return f, apperr.Invalid(field, "That choice is not one this rule can filter on.")
		case allowed == nil && !conditionPattern.MatchString(v):
			return f, apperr.Invalid(field, "That is not a condition.")
		}
		if !slices.Contains(out.Values, v) {
			out.Values = append(out.Values, v)
		}
	}
	if len(out.Values) > 100 {
		return f, apperr.Invalid(field, "Too many choices.")
	}
	return out, nil
}

func cleanListMode(field string, f ListFilter) (ListFilter, error) {
	switch f.Mode {
	case "", ModeAny:
		return ListFilter{Mode: ModeAny, IDs: []uuid.UUID{}}, nil
	case ModeList:
		ids := []uuid.UUID{}
		for _, id := range f.IDs {
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
		if len(ids) > 500 {
			return f, apperr.Invalid(field, "Too many choices.")
		}
		return ListFilter{Mode: ModeList, IDs: ids}, nil
	}
	return f, apperr.Invalid(field, "Choose any or a list.")
}

// checked is a rule's input after validation.
func (s *Service) cleanRule(in Rule, owner uuid.UUID) (Rule, error) {
	var err error
	if in.Name, err = cleanName(in.Name); err != nil {
		return in, err
	}
	switch in.Source {
	case "":
		in.Source = SourceAlerts
	case SourceAlerts, SourceNotices:
	default:
		return in, apperr.Invalid("source", "A rule is about device alerts or about notices.")
	}
	if in.Organizations, err = cleanListMode("organizations", in.Organizations); err != nil {
		return in, err
	}
	if owner != uuid.Nil && in.Organizations.Mode == ModeList {
		return in, apperr.Invalid("organizations", "Only the platform's rules choose organizations.")
	}
	if in.Sites, err = cleanListMode("sites", in.Sites); err != nil {
		return in, err
	}
	if in.Groups, err = cleanListMode("groups", in.Groups); err != nil {
		return in, err
	}
	if in.DeviceKinds, err = cleanValues("deviceKinds", in.DeviceKinds, []string{"server", "workstation"}); err != nil {
		return in, err
	}
	if in.Severities, err = cleanValues("severities", in.Severities, []string{"warning", "critical"}); err != nil {
		return in, err
	}
	if in.Conditions, err = cleanValues("conditions", in.Conditions, nil); err != nil {
		return in, err
	}
	if in.Checks, err = cleanValues("checks", in.Checks, []string{"failing", "errors", "pending", "wear", "temperature"}); err != nil {
		return in, err
	}
	switch {
	case in.WaitMinutes < 0 || in.WaitMinutes > 1440:
		return in, apperr.Invalid("waitMinutes", "Wait from 0 to 1,440 minutes.")
	case in.ReminderHours < 0 || in.ReminderHours > 720:
		return in, apperr.Invalid("reminderHours", "Remind every 0 to 720 hours; 0 is never.")
	case in.IgnoreWindows && owner != uuid.Nil:
		return in, apperr.Invalid("ignoreWindows", "Only the platform's rules may ignore maintenance windows.")
	case len(in.ChannelIDs) < 1 || len(in.ChannelIDs) > MaxRuleChannels:
		return in, apperr.Invalid("channelIds", "Choose from 1 to 20 channels.")
	}
	return in, nil
}

// ruleCols reads a rule's row.
const ruleCols = `r.id, r.organization_id, r.source, r.name, r.enabled, r.orgs_mode, r.sites_mode, r.groups_mode, r.device_kinds, r.severities,
	r.conditions, r.checks, r.wait_minutes, r.on_resolve, r.on_acknowledge, r.reminder_hours, r.ignore_windows, r.group_outages, r.created_at, r.updated_at`

func scanRule(row pgx.Row) (Rule, error) {
	var r Rule
	var dk, sev, cond, chk []string
	if err := row.Scan(&r.ID, &r.OrganizationID, &r.Source, &r.Name, &r.Enabled, &r.Organizations.Mode, &r.Sites.Mode, &r.Groups.Mode, &dk, &sev, &cond, &chk,
		&r.WaitMinutes, &r.OnResolve, &r.OnAcknowledge, &r.ReminderHours, &r.IgnoreWindows, &r.GroupOutages, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return r, err
	}
	r.Platform = r.OrganizationID == nil
	vf := func(v []string) ValueFilter {
		if v == nil {
			return ValueFilter{Mode: ModeAny, Values: []string{}}
		}
		return ValueFilter{Mode: ModeList, Values: v}
	}
	r.DeviceKinds, r.Severities, r.Conditions, r.Checks = vf(dk), vf(sev), vf(cond), vf(chk)
	r.Organizations.IDs, r.Sites.IDs, r.Groups.IDs, r.ChannelIDs = []uuid.UUID{}, []uuid.UUID{}, []uuid.UUID{}, []uuid.UUID{}
	return r, nil
}

// loadRules reads rules (all, or of one owner, or one by ID) with their
// lists and channels.
func loadRules(ctx context.Context, tx pgx.Tx, where string, args ...any) ([]Rule, error) {
	rows, err := tx.Query(ctx, `SELECT `+ruleCols+` FROM notification_rules r `+where+` ORDER BY lower(r.name), r.id`, args...)
	if err != nil {
		return nil, err
	}
	var out []Rule
	byID := map[uuid.UUID]int{}
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		byID[r.ID] = len(out)
		out = append(out, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(out) == 0 {
		return out, err
	}
	ids := make([]uuid.UUID, 0, len(out))
	for _, r := range out {
		ids = append(ids, r.ID)
	}
	pull := func(q string, add func(i int, id uuid.UUID)) error {
		rs, err := tx.Query(ctx, q, ids)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var rid, id uuid.UUID
			if err := rs.Scan(&rid, &id); err != nil {
				return err
			}
			add(byID[rid], id)
		}
		return rs.Err()
	}
	if err := pull(`SELECT rule_id, organization_id FROM notification_rule_orgs WHERE rule_id = ANY ($1) ORDER BY 1, 2`, func(i int, id uuid.UUID) { out[i].Organizations.IDs = append(out[i].Organizations.IDs, id) }); err != nil {
		return nil, err
	}
	if err := pull(`SELECT rule_id, site_id FROM notification_rule_sites WHERE rule_id = ANY ($1) ORDER BY 1, 2`, func(i int, id uuid.UUID) { out[i].Sites.IDs = append(out[i].Sites.IDs, id) }); err != nil {
		return nil, err
	}
	if err := pull(`SELECT rule_id, device_group_id FROM notification_rule_groups WHERE rule_id = ANY ($1) ORDER BY 1, 2`, func(i int, id uuid.UUID) { out[i].Groups.IDs = append(out[i].Groups.IDs, id) }); err != nil {
		return nil, err
	}
	if err := pull(`SELECT rule_id, channel_id FROM notification_rule_channels WHERE rule_id = ANY ($1) ORDER BY 1, 2`, func(i int, id uuid.UUID) { out[i].ChannelIDs = append(out[i].ChannelIDs, id) }); err != nil {
		return nil, err
	}
	for i := range out {
		r := &out[i]
		r.MatchesNothing = (r.Organizations.Mode == ModeList && len(r.Organizations.IDs) == 0) ||
			(r.Sites.Mode == ModeList && len(r.Sites.IDs) == 0) || (r.Groups.Mode == ModeList && len(r.Groups.IDs) == 0)
	}
	return out, nil
}

func arrayOf(f ValueFilter) []string {
	if f.Mode != ModeList {
		return nil
	}
	return f.Values
}

// writeLists replaces a rule's lists and channels, checking what the
// database's composite keys would refuse in words a person can read.
func writeLists(ctx context.Context, tx pgx.Tx, id, owner uuid.UUID, in Rule) error {
	for _, t := range []string{"notification_rule_orgs", "notification_rule_sites", "notification_rule_groups", "notification_rule_channels"} {
		if _, err := tx.Exec(ctx, `DELETE FROM `+t+` WHERE rule_id = $1`, id); err != nil {
			return err
		}
	}
	if in.Organizations.Mode == ModeList {
		var have int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM organizations WHERE id = ANY ($1)`, in.Organizations.IDs).Scan(&have); err != nil {
			return err
		}
		if have != len(in.Organizations.IDs) {
			return apperr.Invalid("organizations", "One of those organizations does not exist.")
		}
		for _, o := range in.Organizations.IDs {
			if _, err := tx.Exec(ctx, `INSERT INTO notification_rule_orgs (rule_id, owner, organization_id) VALUES ($1, $2, $3)`, id, owner, o); err != nil {
				return err
			}
		}
	}
	if in.Sites.Mode == ModeList {
		rows, err := tx.Query(ctx, `SELECT id, organization_id FROM sites WHERE id = ANY ($1) AND ($2::uuid = '00000000-0000-0000-0000-000000000000'::uuid OR organization_id = $2::uuid)`, in.Sites.IDs, owner)
		if err != nil {
			return err
		}
		found := map[uuid.UUID]uuid.UUID{}
		for rows.Next() {
			var s, o uuid.UUID
			if err := rows.Scan(&s, &o); err != nil {
				rows.Close()
				return err
			}
			found[s] = o
		}
		rows.Close()
		if len(found) != len(in.Sites.IDs) {
			return apperr.Invalid("sites", "One of those sites does not exist in this organization.")
		}
		for _, s := range in.Sites.IDs {
			if _, err := tx.Exec(ctx, `INSERT INTO notification_rule_sites (rule_id, owner, organization_id, site_id) VALUES ($1, $2, $3, $4)`, id, owner, found[s], s); err != nil {
				return err
			}
		}
	}
	if in.Groups.Mode == ModeList {
		rows, err := tx.Query(ctx, `SELECT id, site_id, organization_id FROM device_groups WHERE id = ANY ($1) AND ($2::uuid = '00000000-0000-0000-0000-000000000000'::uuid OR organization_id = $2::uuid)`, in.Groups.IDs, owner)
		if err != nil {
			return err
		}
		type g struct{ site, org uuid.UUID }
		found := map[uuid.UUID]g{}
		for rows.Next() {
			var gid uuid.UUID
			var x g
			if err := rows.Scan(&gid, &x.site, &x.org); err != nil {
				rows.Close()
				return err
			}
			found[gid] = x
		}
		rows.Close()
		if len(found) != len(in.Groups.IDs) {
			return apperr.Invalid("groups", "One of those device groups does not exist in this organization.")
		}
		for _, gid := range in.Groups.IDs {
			if _, err := tx.Exec(ctx, `INSERT INTO notification_rule_groups (rule_id, owner, organization_id, site_id, device_group_id) VALUES ($1, $2, $3, $4, $5)`,
				id, owner, found[gid].org, found[gid].site, gid); err != nil {
				return err
			}
		}
	}
	chs := slices.Clone(in.ChannelIDs)
	slices.SortFunc(chs, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	chs = slices.Compact(chs)
	for _, ch := range chs {
		var chOwner uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT owner FROM notification_channels WHERE id = $1`, ch).Scan(&chOwner); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apperr.Invalid("channelIds", "One of those channels does not exist.")
			}
			return err
		}
		if chOwner != owner && chOwner != uuid.Nil {
			return apperr.Invalid("channelIds", "One of those channels does not exist.")
		}
		if _, err := tx.Exec(ctx, `INSERT INTO notification_rule_channels (rule_id, owner, channel_id, channel_owner) VALUES ($1, $2, $3, $4)`, id, owner, ch, chOwner); err != nil {
			if database.ConstraintName(err) == "notification_rule_channels_shared" {
				return apperr.Invalid("channelIds", "That platform channel is not shared with this organization.")
			}
			return err
		}
	}
	return nil
}

func mapRuleErr(err error) error {
	if database.IsUniqueViolation(err) && database.ConstraintName(err) == "notification_rules_name" {
		return apperr.Invalid("name", "Another rule of this owner has that name.")
	}
	return err
}

func ruleDetails(r Rule) map[string]any {
	return map[string]any{"name": r.Name, "source": r.Source, "enabled": r.Enabled, "channels": len(r.ChannelIDs),
		"waitMinutes": r.WaitMinutes, "reminderHours": r.ReminderHours}
}

func writeRule(ctx context.Context, tx pgx.Tx, id uuid.UUID, owner uuid.UUID, in Rule, create bool, by *uuid.UUID) error {
	if create {
		if _, err := tx.Exec(ctx, `INSERT INTO notification_rules (id, organization_id, owner, source, name, enabled, orgs_mode, sites_mode, groups_mode, device_kinds,
				severities, conditions, checks, wait_minutes, on_resolve, on_acknowledge, reminder_hours, ignore_windows, group_outages, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)`,
			id, orgPtr(owner), owner, in.Source, in.Name, in.Enabled, in.Organizations.Mode, in.Sites.Mode, in.Groups.Mode, arrayOf(in.DeviceKinds),
			arrayOf(in.Severities), arrayOf(in.Conditions), arrayOf(in.Checks), in.WaitMinutes, in.OnResolve, in.OnAcknowledge, in.ReminderHours,
			in.IgnoreWindows, in.GroupOutages, by); err != nil {
			return err
		}
	} else if _, err := tx.Exec(ctx, `UPDATE notification_rules SET source = $2, name = $3, enabled = $4, orgs_mode = $5, sites_mode = $6, groups_mode = $7,
			device_kinds = $8, severities = $9, conditions = $10, checks = $11, wait_minutes = $12, on_resolve = $13, on_acknowledge = $14,
			reminder_hours = $15, ignore_windows = $16, group_outages = $17 WHERE id = $1`,
		id, in.Source, in.Name, in.Enabled, in.Organizations.Mode, in.Sites.Mode, in.Groups.Mode, arrayOf(in.DeviceKinds),
		arrayOf(in.Severities), arrayOf(in.Conditions), arrayOf(in.Checks), in.WaitMinutes, in.OnResolve, in.OnAcknowledge, in.ReminderHours,
		in.IgnoreWindows, in.GroupOutages); err != nil {
		return err
	}
	return writeLists(ctx, tx, id, owner, in)
}

// Rules lists the rules of one organization, or, with none, the platform's.
func (s *Service) Rules(ctx context.Context, c access.Caller, org *uuid.UUID) ([]Rule, error) {
	owner := uuid.Nil
	if org != nil {
		owner = *org
	}
	if err := authorize(c, owner); err != nil {
		return nil, err
	}
	var out []Rule
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		var err error
		out, err = loadRules(ctx, tx, `WHERE r.owner = $1`, owner)
		return err
	})
	if out == nil {
		out = []Rule{}
	}
	return out, err
}

// Rule reads one rule.
func (s *Service) Rule(ctx context.Context, c access.Caller, id uuid.UUID) (Rule, error) {
	r, err := s.ruleOf(ctx, id)
	if err != nil {
		return Rule{}, err
	}
	if err := authorize(c, r.owner()); err != nil {
		return Rule{}, err
	}
	return r, nil
}

func (s *Service) ruleOf(ctx context.Context, id uuid.UUID) (Rule, error) {
	var out []Rule
	if err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		var err error
		out, err = loadRules(ctx, tx, `WHERE r.id = $1`, id)
		return err
	}); err != nil {
		return Rule{}, err
	}
	if len(out) == 0 {
		return Rule{}, apperr.NotFound()
	}
	return out[0], nil
}

// CreateRule makes a rule. in.OrganizationID is its owner: nil for the
// platform's.
func (s *Service) CreateRule(ctx context.Context, c access.Caller, in Rule) (Rule, error) {
	owner := in.owner()
	if err := authorize(c, owner); err != nil {
		return Rule{}, err
	}
	in, err := s.cleanRule(in, owner)
	if err != nil {
		return Rule{}, err
	}
	id := uuid.New()
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if owner != uuid.Nil {
			if err := lockChannel(ctx, tx, owner); err != nil {
				return err
			}
			var have int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM notification_rules WHERE owner = $1`, owner).Scan(&have); err != nil {
				return err
			}
			q, err := quotaOf(ctx, tx, owner)
			if err != nil {
				return err
			}
			if have >= q.Rules {
				return ErrRuleQuota
			}
		}
		if err := writeRule(ctx, tx, id, owner, in, true, actorID(c.Actor)); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: ActionRuleCreate, OrganizationID: owner, TargetType: "notification_rule",
			TargetID: id.String(), Outcome: audit.Success, Details: ruleDetails(in)})
	})
	if err != nil {
		return Rule{}, mapRuleErr(err)
	}
	return s.ruleOf(ctx, id)
}

// UpdateRule replaces a rule's settings. What a channel was already told
// keeps the settings it was told under.
func (s *Service) UpdateRule(ctx context.Context, c access.Caller, id uuid.UUID, in Rule) (Rule, error) {
	cur, err := s.Rule(ctx, c, id)
	if err != nil {
		return Rule{}, err
	}
	owner := cur.owner()
	in, err = s.cleanRule(in, owner)
	if err != nil {
		return Rule{}, err
	}
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if err := writeRule(ctx, tx, id, owner, in, false, nil); err != nil {
			return err
		}
		if !in.Enabled {
			if err := forgetUntold(ctx, tx, id); err != nil {
				return err
			}
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: ActionRuleUpdate, OrganizationID: owner, TargetType: "notification_rule",
			TargetID: id.String(), Outcome: audit.Success, Details: ruleDetails(in)})
	})
	if err != nil {
		return Rule{}, mapRuleErr(err)
	}
	return s.ruleOf(ctx, id)
}

// DeleteRule deletes a rule. A channel told that an alert opened is still
// told that it resolved: the settings it was told under are its own.
func (s *Service) DeleteRule(ctx context.Context, c access.Caller, id uuid.UUID) error {
	cur, err := s.Rule(ctx, c, id)
	if err != nil {
		return err
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM notification_rules WHERE id = $1`, id); err != nil {
			return err
		}
		if err := forgetUntold(ctx, tx, id); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: ActionRuleDelete, OrganizationID: cur.owner(), TargetType: "notification_rule",
			TargetID: id.String(), Outcome: audit.Success, Details: map[string]any{"name": cur.Name}})
	})
}

// forgetUntold drops what a rule that is deleted or turned off had yet to
// tell: nothing it has not started telling is sent. What a channel was
// already told of is still told to the end.
func forgetUntold(ctx context.Context, tx pgx.Tx, rule uuid.UUID) error {
	_, err := tx.Exec(ctx, `DELETE FROM alert_notifications WHERE rule_id = $1 AND told_opened_at IS NULL`, rule)
	return err
}
