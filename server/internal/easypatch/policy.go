package easypatch

// EasyPatch's policies, edited from EasyRMM at every level (one-product plan,
// C4): the default policy (super administrators), an organization's, a
// site's and a device's (patch.configure on the organization). Reading a
// level needs patch.view where it applies. EasyRMM resolves what a level
// inherits from the levels above as EasyPatch does (PolicyResolver.Resolve),
// so the editor can show it, and checks a level as EasyPatch does before
// saving it, with field errors EasyPatch does not give.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// The levels of a policy.
const (
	LevelDefault      = "default"
	LevelOrganization = "organization"
	LevelSite         = "site"
	LevelDevice       = "device"
	// LevelTag is a tag's policy, which applies to the devices that have the
	// tag over their site's policy.
	LevelTag = "tag"
)

// PolicyCategories are the update categories a policy can allow; application
// updates are set apart, under ApplicationUpdates.
var PolicyCategories = []string{"Security", "Critical", "Cumulative", "Definition", "ServicingStack", "DotNet", "Feature", "Driver", "Other"}

// defaultLayer is EasyPatch's built-in policy, what the default policy starts
// from (EffectivePolicy.cs).
func defaultLayer() PolicyLayer {
	i := func(v int) *int { return &v }
	b := func(v bool) *bool { return &v }
	start := "02:00"
	return PolicyLayer{
		CheckInIntervalSeconds: i(60), ScanIntervalMinutes: i(360), InventoryIntervalMinutes: i(1440), JitterPercent: i(10),
		AllowedCategories: []string{"Security", "Critical", "Cumulative", "Definition", "ServicingStack", "DotNet", "Other"},
		IncludeOptional:   b(false), ExcludedKbs: []string{}, AcceptEulas: b(true),
		AutoInstallEnabled: b(false), MaintenanceDays: []int{}, MaintenanceStart: &start, MaintenanceDurationMinutes: i(180),
		PreDownloadHours: i(0), InstallDelayDays: i(0), SecurityInstallDelayDays: i(0), KnownExploitedSkipsDelay: b(true),
		ScanStaleAfterHours: i(48), MaxConcurrentInstallsPerSite: i(10),
		TrayIconEnabled: b(true), InstallNotificationsEnabled: b(true), AgentAutoUpdateEnabled: b(true),
		ApplicationUpdates: &ApplicationUpdates{ApprovedApps: []string{}},
		WindowsUpdate:      &LayerWindowsUpdate{},
	}
}

// PolicyView is one level's policy for the editor.
type PolicyView struct {
	Level string `json:"level"`
	// Name is the organization's, site's or device's.
	Name string `json:"name"`
	// Own is the level's own values; nil inherits.
	Own PolicyLayer `json:"own"`
	// HasOwn says the level has a policy of its own.
	HasOwn    bool       `json:"hasOwn"`
	UpdatedAt *time.Time `json:"updatedAt,omitempty"`
	// Inherited is what applies from the levels above, every value set.
	Inherited PolicyLayer `json:"inherited"`
	// InheritedFrom names, for each value Inherited sets, the level it comes
	// from ("Default policy", "Organization", "Site", "Tag Ring 1",
	// "EasyPatch's defaults"), keyed by its JSON name. The maintenance
	// window is keyed maintenanceDays; Windows Update groups
	// windowsUpdate.<group>.
	InheritedFrom map[string]string `json:"inheritedFrom"`
	// TimeZone is the zone of the maintenance window and restart schedule.
	TimeZone string `json:"timeZone,omitempty"`
	// Windows is false for a device that is not a Windows computer, whose
	// Windows settings do not apply.
	Windows bool `json:"windows"`
	CanEdit bool `json:"canEdit"`
	// OrganizationID is the EasyRMM organization, when the level is in one.
	OrganizationID *uuid.UUID `json:"organizationId,omitempty"`
}

// policyTarget is a level resolved to EasyPatch.
type policyTarget struct {
	level, name string
	path        string
	// org is the EasyRMM organization; epOrg EasyPatch's.
	org, epOrg uuid.UUID
	// parents are EasyPatch's paths of the levels above, with their names.
	parents  []namedPath
	endpoint *uuid.UUID
	windows  bool
	timeZone func(ctx context.Context) string
	// target is what an audit record names.
	targetType string
	targetID   uuid.UUID
	// epID is EasyPatch's id of the organization, site, endpoint or tag; kind
	// its collection, where tags are assigned.
	epID uuid.UUID
	kind string
	// everywhere says the level is read and changed with a statement for
	// every organization (a tag's policy, which EasyPatch keeps to super
	// administrators).
	everywhere bool
}

type namedPath struct{ name, path string }

var errNoEngineSite = apperr.Conflict("easypatch_site_not_found", "The patching engine has no site for this site yet: EasyRMM creates it on its next pass, within a minute.")

// policyTarget resolves a level and checks that the caller may read it, and
// edit it when edit is set.
func (s *Service) policyTarget(ctx context.Context, c access.Caller, cl *Client, level string, id uuid.UUID, edit bool) (policyTarget, error) {
	configure := func(org uuid.UUID) error {
		if edit && !c.Can(rbac.PermPatchConfigure, rbac.Org(org)) {
			return apperr.Forbidden()
		}
		return nil
	}
	global := namedPath{"Default policy", globalPolicyPath}
	switch level {
	case LevelDefault:
		if !c.CanAnywhere(rbac.PermPatchView) || (edit && !c.CanGlobal(rbac.PermPatchConfigure)) {
			return policyTarget{}, apperr.Forbidden()
		}
		return policyTarget{level: level, name: "Default policy", path: globalPolicyPath, windows: true, targetType: "patch_policy",
			timeZone: func(context.Context) string { return "" }}, nil

	case LevelTag:
		if !c.CanGlobal(rbac.PermPatchView) {
			return policyTarget{}, apperr.NotFound()
		}
		if edit && !c.CanGlobal(rbac.PermPatchConfigure) {
			return policyTarget{}, apperr.Forbidden()
		}
		tags, err := cl.Tags(s.everywhere(ctx, c, RoleReadOnly))
		if err != nil {
			s.noteError(err)
			return policyTarget{}, epError(err)
		}
		i := slices.IndexFunc(tags, func(t Tag) bool { return t.ID == id })
		if i < 0 {
			return policyTarget{}, apperr.NotFound()
		}
		return policyTarget{level: level, name: tags[i].Name, path: tagPolicyPath(id), parents: []namedPath{global}, windows: true,
			targetType: "patch_tag", epID: id, everywhere: true, timeZone: func(context.Context) string { return "" }}, nil

	case LevelOrganization:
		var name string
		var ep *uuid.UUID
		err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT o.name, l.easypatch_id FROM organizations o
				LEFT JOIN easypatch_organizations l ON l.organization_id = o.id WHERE o.id = $1`, id).Scan(&name, &ep)
		})
		switch {
		case errors.Is(err, pgx.ErrNoRows) || (err == nil && !c.CanInOrg(rbac.PermPatchView, id)):
			return policyTarget{}, apperr.NotFound()
		case err != nil:
			return policyTarget{}, err
		case !c.Can(rbac.PermPatchView, rbac.Org(id)):
			return policyTarget{}, apperr.Forbidden()
		case ep == nil:
			return policyTarget{}, errOrgNotLinked
		}
		if err := configure(id); err != nil {
			return policyTarget{}, err
		}
		epOrg := *ep
		return policyTarget{level: level, name: name, path: organizationPolicyPath(epOrg), org: id, epOrg: epOrg,
			parents: []namedPath{global}, windows: true, targetType: "organization", targetID: id, epID: epOrg, kind: "organizations",
			timeZone: func(ctx context.Context) string {
				o, err := cl.GetOrganization(ctx, epOrg)
				if err != nil {
					return ""
				}
				return o.TimeZone
			}}, nil

	case LevelSite:
		var org uuid.UUID
		var name string
		var ep, epSite *uuid.UUID
		err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT s.organization_id, s.name, l.easypatch_id, ls.easypatch_id FROM sites s
				LEFT JOIN easypatch_organizations l ON l.organization_id = s.organization_id
				LEFT JOIN easypatch_sites ls ON ls.site_id = s.id WHERE s.id = $1`, id).Scan(&org, &name, &ep, &epSite)
		})
		switch {
		case errors.Is(err, pgx.ErrNoRows) || (err == nil && !c.Can(rbac.PermPatchView, rbac.Site(org, id))):
			return policyTarget{}, apperr.NotFound()
		case err != nil:
			return policyTarget{}, err
		case ep == nil:
			return policyTarget{}, errOrgNotLinked
		}
		if err := configure(org); err != nil {
			return policyTarget{}, err
		}
		if epSite == nil {
			// A site the reconciler has not recorded yet is found by name,
			// as installs do.
			sites, err := cl.Sites(s.as(ctx, c, RoleReadOnly, *ep), *ep)
			if err != nil {
				s.noteError(err)
				return policyTarget{}, epError(err)
			}
			for _, x := range sites {
				if strings.EqualFold(strings.TrimSpace(x.Name), strings.TrimSpace(name)) {
					epSite = &x.ID
					break
				}
			}
			if epSite == nil {
				return policyTarget{}, errNoEngineSite
			}
		}
		epOrg, siteID := *ep, *epSite
		return policyTarget{level: level, name: name, path: sitePolicyPath(siteID), org: org, epOrg: epOrg,
			parents: []namedPath{global, {"Organization", organizationPolicyPath(epOrg)}}, windows: true, targetType: "site", targetID: id,
			epID: siteID, kind: "sites",
			timeZone: func(ctx context.Context) string {
				if st, err := cl.GetSite(ctx, siteID); err == nil && st.TimeZone != "" {
					return st.TimeZone
				}
				if o, err := cl.GetOrganization(ctx, epOrg); err == nil {
					return o.TimeZone
				}
				return ""
			}}, nil

	case LevelDevice:
		d, err := s.device(ctx, c, id, rbac.PermPatchView)
		if err != nil {
			return policyTarget{}, err
		}
		if d.endpointID == nil || d.easyPatchOrg == nil {
			return policyTarget{}, apperr.Conflict("easypatch_not_linked", "This device is not patched through EasyPatch.")
		}
		if err := configure(d.organizationID); err != nil {
			return policyTarget{}, err
		}
		t := policyTarget{level: level, name: d.name, path: endpointPolicyPath(*d.endpointID), org: d.organizationID, epOrg: *d.easyPatchOrg,
			endpoint: d.endpointID, windows: d.platform == "windows", targetType: "device", targetID: d.id, epID: *d.endpointID, kind: "endpoints"}
		t.parents = []namedPath{global, {"Organization", organizationPolicyPath(t.epOrg)}}
		var zone string
		t.timeZone = func(context.Context) string { return zone }
		e, err := cl.Endpoint(s.as(ctx, c, RoleReadOnly, t.epOrg), *d.endpointID)
		switch {
		case IsStatus(err, http.StatusNotFound):
			return policyTarget{}, apperr.Conflict("easypatch_endpoint_gone", "EasyPatch no longer lists this device's endpoint.")
		case err != nil:
			s.noteError(err)
			return policyTarget{}, epError(err)
		}
		if e.Summary.SiteID != nil {
			t.parents = append(t.parents, namedPath{"Site", sitePolicyPath(*e.Summary.SiteID)})
		}
		if ep, err := cl.EffectivePolicy(s.as(ctx, c, RoleReadOnly, t.epOrg), *d.endpointID); err == nil {
			zone = ep.TimeZone
		}
		return t, nil
	}
	return policyTarget{}, errLevel
}

var errLevel = apperr.Invalid("level", "Choose default, organization, site, device or tag.")

// Policy reads a level's policy, with what it inherits.
func (s *Service) Policy(ctx context.Context, c access.Caller, level string, id uuid.UUID) (PolicyView, error) {
	r, cl, err := s.conn(ctx)
	if err != nil {
		return PolicyView{}, err
	}
	if r == nil {
		return PolicyView{}, errNotConfigured
	}
	t, err := s.policyTarget(ctx, c, cl, level, id, false)
	if err != nil {
		return PolicyView{}, err
	}
	return s.policyView(ctx, c, cl, r, t)
}

func (s *Service) policyView(ctx context.Context, c access.Caller, cl *Client, r *connRow, t policyTarget) (PolicyView, error) {
	rctx := s.as(ctx, c, RoleReadOnly, t.epOrg)
	if t.everywhere {
		rctx = s.everywhere(ctx, c, RoleSuperAdmin)
	}
	own, err := cl.LevelPolicy(rctx, t.path)
	if err != nil {
		s.noteError(err)
		return PolicyView{}, epError(err)
	}
	layers := []namedLayer{}
	for _, p := range t.parents {
		lp, err := cl.LevelPolicy(rctx, p.path)
		switch {
		case IsStatus(err, http.StatusNotFound):
			continue
		case err != nil:
			s.noteError(err)
			return PolicyView{}, epError(err)
		}
		layers = append(layers, namedLayer{p.name, lp.PolicyLayer})
	}
	if t.endpoint != nil {
		tags, err := cl.TagPolicies(rctx, *t.endpoint)
		if err != nil {
			s.noteError(err)
			return PolicyView{}, epError(err)
		}
		for _, tp := range tags {
			layers = append(layers, namedLayer{"Tag " + tp.Tag.Name, tp.Policy.PolicyLayer})
		}
	}
	inherited, from := resolvePolicy(layers)
	v := PolicyView{Level: t.level, Name: t.name, Own: own.PolicyLayer, HasOwn: own.ID != nil, UpdatedAt: own.UpdatedAt,
		Inherited: inherited, InheritedFrom: from, TimeZone: t.timeZone(rctx), Windows: t.windows,
		CanEdit: s.canEditPolicy(c, t)}
	if t.org != uuid.Nil {
		org := t.org
		v.OrganizationID = &org
	}
	if t.level == LevelDefault {
		// The default policy always has every value; EasyPatch fills in its
		// own defaults.
		v.HasOwn = true
	}
	v.Own.ExcludedKbs = orEmpty(v.Own.ExcludedKbs)
	return v, nil
}

func (s *Service) canEditPolicy(c access.Caller, t policyTarget) bool {
	if t.level == LevelDefault || t.level == LevelTag {
		return c.CanGlobal(rbac.PermPatchConfigure)
	}
	return c.Can(rbac.PermPatchConfigure, rbac.Org(t.org))
}

// policyWriter is ctx with the statement a change to the level needs.
func (s *Service) policyWriter(ctx context.Context, c access.Caller, t policyTarget) context.Context {
	if t.level == LevelDefault || t.level == LevelTag {
		return s.everywhere(ctx, c, RoleSuperAdmin)
	}
	return s.as(ctx, c, RoleAdmin, t.epOrg)
}

// everywhere returns ctx carrying a statement for every organization, for
// what EasyPatch keeps to administrators without organization restrictions.
func (s *Service) everywhere(ctx context.Context, c access.Caller, role string) context.Context {
	st := s.statement(c, role)
	st.AllOrganizations = true
	return WithStatement(ctx, st)
}

// SavePolicy replaces a level's own policy.
func (s *Service) SavePolicy(ctx context.Context, c access.Caller, level string, id uuid.UUID, in PolicyLayer) (PolicyView, error) {
	r, cl, err := s.operable(ctx)
	if err != nil {
		return PolicyView{}, err
	}
	t, err := s.policyTarget(ctx, c, cl, level, id, true)
	if err != nil {
		return PolicyView{}, err
	}
	before, err := s.policyView(ctx, c, cl, r, t)
	if err != nil {
		return PolicyView{}, err
	}
	if err := normalizePolicy(&in, t.level, before.Inherited); err != nil {
		return PolicyView{}, err
	}
	if _, err := cl.SetLevelPolicy(s.policyWriter(ctx, c, t), t.path, in, c.Actor.Label); err != nil {
		s.noteError(err)
		return PolicyView{}, epError(err)
	}
	changed := changedPolicyFields(before.Own, in)
	if err := s.recordPolicy(ctx, c, t, "patch.policy_update", map[string]any{"changed": changed}); err != nil {
		return PolicyView{}, err
	}
	s.fleet.clear()
	return s.policyView(ctx, c, cl, r, t)
}

// ResetPolicy removes a level's own policy, so it inherits everything; the
// default policy goes back to EasyPatch's own defaults.
func (s *Service) ResetPolicy(ctx context.Context, c access.Caller, level string, id uuid.UUID) (PolicyView, error) {
	r, cl, err := s.operable(ctx)
	if err != nil {
		return PolicyView{}, err
	}
	t, err := s.policyTarget(ctx, c, cl, level, id, true)
	if err != nil {
		return PolicyView{}, err
	}
	wctx := s.policyWriter(ctx, c, t)
	if t.level == LevelDefault {
		_, err = cl.SetLevelPolicy(wctx, t.path, PolicyLayer{}, c.Actor.Label)
	} else {
		err = cl.DeleteLevelPolicy(wctx, t.path, c.Actor.Label)
	}
	if err != nil {
		s.noteError(err)
		return PolicyView{}, epError(err)
	}
	if err := s.recordPolicy(ctx, c, t, "patch.policy_reset", map[string]any{}); err != nil {
		return PolicyView{}, err
	}
	s.fleet.clear()
	return s.policyView(ctx, c, cl, r, t)
}

func (s *Service) recordPolicy(ctx context.Context, c access.Caller, t policyTarget, action string, details map[string]any) error {
	details["level"], details["name"] = t.level, t.name
	ev := audit.Event{Actor: c.Actor, Action: action, TargetType: t.targetType, Outcome: audit.Success, Details: details}
	if t.targetID != uuid.Nil {
		ev.TargetID = t.targetID.String()
	}
	if t.org != uuid.Nil {
		ev.OrganizationID = t.org
	}
	return s.record(ctx, []audit.Event{ev})
}

type namedLayer struct {
	name string
	p    PolicyLayer
}

// policyKey is a field's JSON name.
func policyKey(f reflect.StructField) string {
	name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
	return name
}

// unitFields override as a unit, or add up, and are resolved apart from the
// plain values.
var unitFields = map[string]bool{"allowedCategories": true, "excludedKbs": true, "maintenanceDays": true, "maintenanceStart": true,
	"maintenanceDurationMinutes": true, "restartSchedule": true, "windowsUpdate": true, "applicationUpdates": true}

// resolvePolicy applies the layers over EasyPatch's defaults as EasyPatch
// does, and says where each value comes from.
func resolvePolicy(layers []namedLayer) (PolicyLayer, map[string]string) {
	out := defaultLayer()
	from := map[string]string{}
	const builtIn = "EasyPatch's defaults"
	ov := reflect.ValueOf(&out).Elem()
	typ := ov.Type()
	for i := range typ.NumField() {
		if k := policyKey(typ.Field(i)); !unitFields[k] {
			from[k] = builtIn
		}
	}
	for _, k := range []string{"allowedCategories", "maintenanceDays", "restartSchedule", "applicationUpdates",
		"windowsUpdate.automaticUpdates", "windowsUpdate.featureUpdates", "windowsUpdate.qualityUpdates", "windowsUpdate.restartBehavior"} {
		from[k] = builtIn
	}
	kbs := []string{}
	for _, l := range layers {
		lv := reflect.ValueOf(l.p)
		for i := range typ.NumField() {
			k := policyKey(typ.Field(i))
			if unitFields[k] || lv.Field(i).IsNil() {
				continue
			}
			ov.Field(i).Set(lv.Field(i))
			from[k] = l.name
		}
		if l.p.AllowedCategories != nil {
			out.AllowedCategories, from["allowedCategories"] = l.p.AllowedCategories, l.name
		}
		if l.p.MaintenanceDays != nil {
			start, length := "02:00", 180
			if l.p.MaintenanceStart != nil {
				start = *l.p.MaintenanceStart
			}
			if l.p.MaintenanceDurationMinutes != nil {
				length = *l.p.MaintenanceDurationMinutes
			}
			out.MaintenanceDays, out.MaintenanceStart, out.MaintenanceDurationMinutes = l.p.MaintenanceDays, &start, &length
			from["maintenanceDays"] = l.name
		}
		if l.p.RestartSchedule != nil {
			out.RestartSchedule, from["restartSchedule"] = l.p.RestartSchedule, l.name
		}
		if l.p.ApplicationUpdates != nil {
			out.ApplicationUpdates, from["applicationUpdates"] = l.p.ApplicationUpdates, l.name
		}
		if w := l.p.WindowsUpdate; w != nil {
			if w.AutomaticUpdates != nil {
				out.WindowsUpdate.AutomaticUpdates, from["windowsUpdate.automaticUpdates"] = w.AutomaticUpdates, l.name
			}
			if w.FeatureUpdates != nil {
				out.WindowsUpdate.FeatureUpdates, from["windowsUpdate.featureUpdates"] = w.FeatureUpdates, l.name
			}
			if w.QualityUpdates != nil {
				out.WindowsUpdate.QualityUpdates, from["windowsUpdate.qualityUpdates"] = w.QualityUpdates, l.name
			}
			if w.RestartBehavior != nil {
				out.WindowsUpdate.RestartBehavior, from["windowsUpdate.restartBehavior"] = w.RestartBehavior, l.name
			}
		}
		for _, kb := range l.p.ExcludedKbs {
			if n := normalizeKB(kb); n != "" && !slices.Contains(kbs, n) {
				kbs = append(kbs, n)
			}
		}
	}
	out.ExcludedKbs = kbs
	return out, from
}

// changedPolicyFields names the values a save changes, for the audit trail.
func changedPolicyFields(before, after PolicyLayer) []string {
	out := []string{}
	bv, av := reflect.ValueOf(before), reflect.ValueOf(after)
	typ := bv.Type()
	for i := range typ.NumField() {
		b, a := bv.Field(i).Interface(), av.Field(i).Interface()
		if k := policyKey(typ.Field(i)); k == "excludedKbs" {
			if !slices.Equal(orEmpty(before.ExcludedKbs), orEmpty(after.ExcludedKbs)) {
				out = append(out, k)
			}
		} else if !reflect.DeepEqual(b, a) {
			out = append(out, k)
		}
	}
	return out
}

var (
	hhmm        = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)
	wingetID    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_+\-]*(\.[A-Za-z0-9_+\-]+)+$`)
	releaseName = regexp.MustCompile(`^\d{2}H[12]$`)
)

// normalizeKB is "KB" and its number, or "" when it is not one.
func normalizeKB(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && strings.EqualFold(s[:2], "KB") {
		s = s[2:]
	}
	if len(s) == 0 || len(s) > 10 {
		return ""
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return "KB" + s
}

// normalizePolicy checks a level's policy as EasyPatch does, and refuses what
// would stop patching without saying so: no category to install, or
// automatic installs with no maintenance window.
func normalizePolicy(p *PolicyLayer, level string, inherited PolicyLayer) error {
	f := apperr.Fields{}
	bad := f.Add
	rng := func(field string, v *int, lo, hi int, what string) {
		if v != nil && (*v < lo || *v > hi) {
			bad(field, fmt.Sprintf("Choose %s from %d to %d.", what, lo, hi))
		}
	}
	rng("checkInIntervalSeconds", p.CheckInIntervalSeconds, 15, 3600, "a check-in interval (seconds)")
	rng("scanIntervalMinutes", p.ScanIntervalMinutes, 30, 10080, "a scan interval (minutes)")
	rng("inventoryIntervalMinutes", p.InventoryIntervalMinutes, 60, 10080, "an inventory interval (minutes)")
	rng("jitterPercent", p.JitterPercent, 0, 50, "a spread (percent)")
	rng("maintenanceDurationMinutes", p.MaintenanceDurationMinutes, 15, 1440, "a window length (minutes)")
	rng("preDownloadHours", p.PreDownloadHours, 0, 24, "hours ahead")
	rng("scanStaleAfterHours", p.ScanStaleAfterHours, 1, 720, "hours")
	rng("maxConcurrentInstallsPerSite", p.MaxConcurrentInstallsPerSite, 1, 1000, "a limit")
	rng("installDelayDays", p.InstallDelayDays, 0, 365, "a delay (days)")
	rng("securityInstallDelayDays", p.SecurityInstallDelayDays, 0, 90, "a delay (days)")
	if (level == LevelDevice || level == LevelTag) && p.MaxConcurrentInstallsPerSite != nil {
		bad("maxConcurrentInstallsPerSite", "Only the default policy, an organization or a site sets a limit for a site.")
	}

	if p.AllowedCategories != nil {
		seen := []string{}
		for _, c := range p.AllowedCategories {
			i := slices.IndexFunc(PolicyCategories, func(k string) bool { return strings.EqualFold(k, c) })
			if i < 0 {
				bad("allowedCategories", fmt.Sprintf("%q is not a category; application updates are set apart.", c))
				continue
			}
			if !slices.Contains(seen, PolicyCategories[i]) {
				seen = append(seen, PolicyCategories[i])
			}
		}
		if len(p.AllowedCategories) == 0 {
			bad("allowedCategories", "Choose at least one category.")
		}
		p.AllowedCategories = seen
	}

	if p.MaintenanceDays != nil {
		days := []int{}
		for _, d := range p.MaintenanceDays {
			if d < 0 || d > 6 {
				bad("maintenanceDays", "Days are 0 (Sunday) to 6 (Saturday).")
			} else if !slices.Contains(days, d) {
				days = append(days, d)
			}
		}
		slices.Sort(days)
		p.MaintenanceDays = days
		if p.MaintenanceStart == nil {
			start := "02:00"
			p.MaintenanceStart = &start
		}
		if p.MaintenanceDurationMinutes == nil {
			length := 180
			p.MaintenanceDurationMinutes = &length
		}
	} else if p.MaintenanceStart != nil || p.MaintenanceDurationMinutes != nil {
		bad("maintenanceDays", "Choose the window's days with its start and length.")
	}
	if p.MaintenanceStart != nil && !hhmm.MatchString(*p.MaintenanceStart) {
		bad("maintenanceStart", "Give a time as in 02:00.")
	}
	// EasyPatch installs automatically only in a maintenance window, so a
	// level that turns automatic installs on, or changes the window, must
	// leave one. A level that touches neither is not held to its parents'.
	autoInstall := inherited.AutoInstallEnabled != nil && *inherited.AutoInstallEnabled
	if p.AutoInstallEnabled != nil {
		autoInstall = *p.AutoInstallEnabled
	}
	window := inherited.MaintenanceDays
	if p.MaintenanceDays != nil {
		window = p.MaintenanceDays
	}
	// A tag's devices take their window from their own organization or site
	// when the tag sets none, so a tag is held to the window it sets.
	if level == LevelTag && p.MaintenanceDays == nil {
		window = []int{0}
	}
	if (p.AutoInstallEnabled != nil || p.MaintenanceDays != nil) && autoInstall && len(window) == 0 {
		bad("maintenanceDays", "Automatic installs happen only in the maintenance window: choose its days.")
	}

	kbs := []string{}
	for _, kb := range p.ExcludedKbs {
		n := normalizeKB(kb)
		if n == "" {
			bad("excludedKbs", fmt.Sprintf("%q is not a KB number such as KB5044284.", kb))
		} else if !slices.Contains(kbs, n) {
			kbs = append(kbs, n)
		}
	}
	p.ExcludedKbs = kbs

	if rs := p.RestartSchedule; rs != nil {
		normalizeRestartSchedule(rs, bad)
	}
	if w := p.WindowsUpdate; w != nil {
		normalizeWindowsUpdate(w, bad)
	}
	if a := p.ApplicationUpdates; a != nil {
		apps := []string{}
		for _, id := range a.ApprovedApps {
			id = strings.TrimSpace(id)
			switch {
			case len(id) <= 2 || len(id) > 128 || !wingetID.MatchString(id):
				bad("applicationUpdates", fmt.Sprintf("%q is not a winget package ID such as Mozilla.Firefox.", id))
			case !slices.ContainsFunc(apps, func(x string) bool { return strings.EqualFold(x, id) }):
				apps = append(apps, id)
			}
		}
		if len(apps) > 100 {
			bad("applicationUpdates", "Approve at most 100 applications.")
		}
		a.ApprovedApps = apps
	}
	return f.Err()
}

func normalizeRestartSchedule(rs *RestartSchedule, bad func(field, msg string)) {
	if rs.Time == "" {
		rs.Time = "03:00"
	}
	if rs.Condition == "" {
		rs.Condition = "OnlyIfPending"
	}
	if rs.Mode == "" {
		rs.Mode = "PromptWithDeadline"
	}
	for _, d := range []struct {
		v   *int
		def int
	}{{&rs.CountdownMinutes, 5}, {&rs.DeadlineMinutes, 240}, {&rs.ExpiryMinutes, 120}} {
		if *d.v == 0 {
			*d.v = d.def
		}
	}
	days := []int{}
	for _, d := range rs.Days {
		if d >= 0 && d <= 6 && !slices.Contains(days, d) {
			days = append(days, d)
		} else if d < 0 || d > 6 {
			bad("restartSchedule", "Days are 0 (Sunday) to 6 (Saturday).")
		}
	}
	slices.Sort(days)
	rs.Days = days
	if !rs.Enabled {
		return
	}
	switch {
	case len(days) == 0:
		bad("restartSchedule", "Choose at least one day for the restart schedule.")
	case !hhmm.MatchString(rs.Time):
		bad("restartSchedule", "Give the restart time as in 03:00.")
	case !slices.Contains(restartConditions, rs.Condition):
		bad("restartSchedule", "Choose whether it restarts only when a restart is pending.")
	case !slices.Contains(restartModes, rs.Mode):
		bad("restartSchedule", "Choose how the people signed in are asked.")
	case rs.Mode == "Countdown" && (rs.CountdownMinutes < 1 || rs.CountdownMinutes > 60):
		bad("restartSchedule", "Choose a countdown of 1 to 60 minutes.")
	case rs.Mode == "PromptWithDeadline" && (rs.DeadlineMinutes < 15 || rs.DeadlineMinutes > 7*24*60):
		bad("restartSchedule", "Choose a deadline from 15 minutes to 7 days.")
	case rs.ExpiryMinutes < 15 || rs.ExpiryMinutes > 24*60:
		bad("restartSchedule", "A scheduled restart can wait 15 minutes to 24 hours for an offline computer.")
	}
}

var automaticUpdateModes = []string{"Disabled", "NotifyDownload", "AutoDownloadNotifyInstall", "AutoDownloadScheduleInstall"}

func normalizeWindowsUpdate(w *LayerWindowsUpdate, bad func(field, msg string)) {
	unmanaged := func(managed bool, hasValue bool, field string) bool {
		if managed && !hasValue {
			bad(field, "Choose the settings to apply, or leave Windows alone.")
		}
		return !managed
	}
	if g := w.AutomaticUpdates; g != nil {
		if unmanaged(g.Managed, g.Value != nil, "windowsUpdate.automaticUpdates") {
			g.Value = nil
		} else if v := g.Value; v != nil {
			switch {
			case !slices.Contains(automaticUpdateModes, v.Mode):
				bad("windowsUpdate.automaticUpdates", "Choose how Windows updates itself.")
			case v.ScheduledInstallDay < 0 || v.ScheduledInstallDay > 7:
				bad("windowsUpdate.automaticUpdates", "Choose every day, or one day of the week.")
			case v.ScheduledInstallHour < 0 || v.ScheduledInstallHour > 23:
				bad("windowsUpdate.automaticUpdates", "Choose an hour from 0 to 23.")
			}
		}
	}
	if g := w.FeatureUpdates; g != nil {
		if unmanaged(g.Managed, g.Value != nil, "windowsUpdate.featureUpdates") {
			g.Value = nil
		} else if v := g.Value; v != nil {
			v.TargetProductVersion, v.TargetReleaseVersion = strings.TrimSpace(v.TargetProductVersion), strings.ToUpper(strings.TrimSpace(v.TargetReleaseVersion))
			switch {
			case v.DeferDays != nil && (*v.DeferDays < 0 || *v.DeferDays > 365):
				bad("windowsUpdate.featureUpdates", "Defer feature updates by 0 to 365 days.")
			case (v.TargetProductVersion == "") != (v.TargetReleaseVersion == ""):
				bad("windowsUpdate.featureUpdates", "To keep a Windows version, give both the product and the version (for example 24H2).")
			case v.TargetProductVersion != "" && v.TargetProductVersion != "Windows 10" && v.TargetProductVersion != "Windows 11":
				bad("windowsUpdate.featureUpdates", "The product is Windows 10 or Windows 11.")
			case v.TargetReleaseVersion != "" && !releaseName.MatchString(v.TargetReleaseVersion):
				bad("windowsUpdate.featureUpdates", "The version looks like 24H2.")
			}
		}
	}
	if g := w.QualityUpdates; g != nil {
		if unmanaged(g.Managed, g.Value != nil, "windowsUpdate.qualityUpdates") {
			g.Value = nil
		} else if v := g.Value; v != nil && v.DeferDays != nil && (*v.DeferDays < 0 || *v.DeferDays > 30) {
			bad("windowsUpdate.qualityUpdates", "Defer quality updates by 0 to 30 days.")
		}
	}
	if g := w.RestartBehavior; g != nil {
		if unmanaged(g.Managed, g.Value != nil, "windowsUpdate.restartBehavior") {
			g.Value = nil
		} else if v := g.Value; v != nil {
			switch {
			case (v.ActiveHoursStart == nil) != (v.ActiveHoursEnd == nil):
				bad("windowsUpdate.restartBehavior", "Give both the start and the end of active hours.")
			case v.ActiveHoursStart == nil:
			case *v.ActiveHoursStart < 0 || *v.ActiveHoursStart > 23 || *v.ActiveHoursEnd < 0 || *v.ActiveHoursEnd > 23:
				bad("windowsUpdate.restartBehavior", "Active hours are 0 to 23.")
			case *v.ActiveHoursStart == *v.ActiveHoursEnd || (*v.ActiveHoursEnd-*v.ActiveHoursStart+24)%24 > 18:
				bad("windowsUpdate.restartBehavior", "Active hours span 1 to 18 hours.")
			}
		}
	}
}

// ParsePolicyLevel checks a level's name.
func ParsePolicyLevel(s string) (string, error) {
	switch s {
	case LevelDefault, LevelOrganization, LevelSite, LevelDevice, LevelTag:
		return s, nil
	}
	return "", errLevel
}
