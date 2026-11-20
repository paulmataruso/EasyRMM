package easypatch

import (
	"cmp"
	"context"
	"slices"
	"strings"
	"unicode"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Patching → Alerts (one-product plan, C7): the alerts EasyPatch raises,
// as the caller may see them, and acknowledging them.

// The values EasyPatch's alert filters take.
var (
	AlertStatuses   = []string{"unresolved", "open", "acknowledged", "resolved", "all"}
	AlertSeverities = []string{"Critical", "Warning", "Info"}
	AlertRuleKinds  = []string{"EndpointOffline", "InstallFailed", "SecurityUpdateMissing", "ScanStale", "RestartPending",
		"EnrollmentPending", "OsUnsupported", "KnownExploitedMissing", "UpdateHeld"}
)

// maxAcknowledge is how many alerts one request acknowledges.
const maxAcknowledge = 200

// ackPages is how many pages of an organization's open alerts
// acknowledging looks through for the alerts asked for.
const ackPages = 25

// AlertsQuery narrows the alert list: to an organization or one device, and
// by EasyPatch's status, severity, rule type and words in the title.
type AlertsQuery struct {
	OrganizationID, DeviceID           uuid.UUID
	Status, Severity, RuleType, Search string
}

func (q *AlertsQuery) validate() error {
	q.Search = strings.TrimSpace(q.Search)
	switch {
	case q.Status != "" && !slices.Contains(AlertStatuses, q.Status):
		return apperr.Invalid("status", "Choose open, acknowledged, resolved, unresolved or all.")
	case q.Severity != "" && !slices.Contains(AlertSeverities, q.Severity):
		return apperr.Invalid("severity", "Choose a severity.")
	case q.RuleType != "" && !slices.Contains(AlertRuleKinds, q.RuleType):
		return apperr.Invalid("ruleType", "Choose a type of alert.")
	case len([]rune(q.Search)) > 200 || strings.ContainsFunc(q.Search, unicode.IsControl):
		return apperr.Invalid("search", "Search for at most 200 characters.")
	}
	return nil
}

// AlertView is an alert with EasyRMM's organization and device, and
// whether the caller may acknowledge it.
type AlertView struct {
	Alert
	// OrganizationID and OrganizationName are EasyRMM's.
	OrganizationID   uuid.UUID `json:"organizationId"`
	OrganizationName string    `json:"organizationName"`
	// DeviceID is the EasyRMM device the endpoint is, when one is linked.
	DeviceID       *uuid.UUID `json:"deviceId,omitempty"`
	DeviceName     string     `json:"deviceName,omitempty"`
	CanAcknowledge bool       `json:"canAcknowledge"`
	siteID         uuid.UUID
}

// AlertList is the alerts that match, at most PageSize; Capped says there
// may be more.
type AlertList struct {
	Items  []AlertView `json:"items"`
	Capped bool        `json:"capped"`
}

// alertOrganizations lists the linked organizations (or the one asked for)
// where the caller holds perm somewhere.
func (s *Service) alertOrganizations(ctx context.Context, c access.Caller, org uuid.UUID, perm rbac.Permission) ([]reportOrg, error) {
	all, err := s.linkedOrganizations(ctx, c, org)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(all, func(o reportOrg) bool { return !c.CanInOrg(perm, o.id) }), nil
}

// alertViews keeps the alerts the caller may see: a device's when they see
// its patching, an organization's (or of an endpoint EasyRMM does not
// link) when they see the whole organization's.
func (s *Service) alertViews(ctx context.Context, c access.Caller, orgs []reportOrg, alerts []Alert) ([]AlertView, error) {
	byEngine := map[uuid.UUID]reportOrg{}
	for _, o := range orgs {
		byEngine[o.ep] = o
	}
	var endpoints []uuid.UUID
	for _, a := range alerts {
		if a.EndpointID != nil {
			endpoints = append(endpoints, *a.EndpointID)
		}
	}
	devices, err := s.linkedDevices(ctx, c, endpoints)
	if err != nil {
		return nil, err
	}
	out := []AlertView{}
	for _, a := range alerts {
		o, ok := byEngine[a.OrganizationID]
		if !ok {
			continue
		}
		v := AlertView{Alert: a, OrganizationID: o.id, OrganizationName: o.name}
		res := rbac.Org(o.id)
		if d, ok := devices[idOf(a.EndpointID)]; ok && a.EndpointID != nil {
			v.DeviceID, v.DeviceName, v.siteID, res = &d.id, d.name, d.siteID, d.resource()
		} else if !c.Can(rbac.PermPatchView, rbac.Org(o.id)) {
			continue
		}
		v.CanAcknowledge = a.Status == "Open" && c.Can(rbac.PermPatchManage, res)
		out = append(out, v)
	}
	return out, nil
}

func idOf(id *uuid.UUID) uuid.UUID {
	if id == nil {
		return uuid.Nil
	}
	return *id
}

var severityRank = map[string]int{"Critical": 2, "Warning": 1}

// sortAlerts orders alerts as EasyPatch does: unresolved first, then the
// most severe, then the newest.
func sortAlerts(list []AlertView) {
	slices.SortStableFunc(list, func(a, b AlertView) int {
		ra, rb := a.Status == "Resolved", b.Status == "Resolved"
		switch {
		case ra != rb && ra:
			return 1
		case ra != rb:
			return -1
		}
		return cmp.Or(severityRank[b.Severity]-severityRank[a.Severity], b.OpenedAt.Compare(a.OpenedAt))
	})
}

// Alerts lists the newest EasyPatch alerts the caller may see that match,
// at most PageSize.
func (s *Service) Alerts(ctx context.Context, c access.Caller, q AlertsQuery) (AlertList, error) {
	if !c.CanAnywhere(rbac.PermPatchView) {
		return AlertList{}, apperr.Forbidden()
	}
	if err := q.validate(); err != nil {
		return AlertList{}, err
	}
	r, cl, err := s.conn(ctx)
	if err != nil {
		return AlertList{}, err
	}
	if r == nil {
		return AlertList{}, errNotConfigured
	}
	orgs, err := s.alertOrganizations(ctx, c, q.OrganizationID, rbac.PermPatchView)
	if err != nil {
		return AlertList{}, err
	}
	filter := AlertFilter{Status: q.Status, Severity: q.Severity, RuleType: q.RuleType, Search: q.Search}
	if q.DeviceID != uuid.Nil {
		d, err := s.device(ctx, c, q.DeviceID, rbac.PermPatchView)
		if err != nil {
			return AlertList{}, err
		}
		if d.endpointID == nil || d.easyPatchOrg == nil {
			return AlertList{Items: []AlertView{}}, nil
		}
		filter.EndpointID = *d.endpointID
		orgs = slices.DeleteFunc(orgs, func(o reportOrg) bool { return o.ep != *d.easyPatchOrg })
	}
	var alerts []Alert
	capped := false
	for _, o := range orgs {
		filter.OrganizationID = o.ep
		p, err := cl.Alerts(s.as(ctx, c, RoleReadOnly, o.ep), filter, 1, PageSize)
		if err != nil {
			s.noteError(err)
			return AlertList{}, epError(err)
		}
		alerts = append(alerts, p.Items...)
		capped = capped || p.TotalCount > len(p.Items)
	}
	out, err := s.alertViews(ctx, c, orgs, alerts)
	if err != nil {
		return AlertList{}, err
	}
	sortAlerts(out)
	if len(out) > PageSize {
		out, capped = out[:PageSize], true
	}
	return AlertList{Items: out, Capped: capped}, nil
}

// AlertCounts counts the unresolved alerts the caller may see. Capped says
// an organization had more than PageSize to count one by one, so the counts
// may be low.
type AlertCounts struct {
	AlertSummary
	Capped bool `json:"capped"`
}

// AlertCounts counts the unresolved alerts the caller may see, in one
// organization or all. EasyPatch counts those of the organizations the
// caller sees whole; EasyRMM counts the rest, of the devices they see.
func (s *Service) AlertCounts(ctx context.Context, c access.Caller, org uuid.UUID) (AlertCounts, error) {
	if !c.CanAnywhere(rbac.PermPatchView) {
		return AlertCounts{}, apperr.Forbidden()
	}
	r, cl, err := s.conn(ctx)
	if err != nil {
		return AlertCounts{}, err
	}
	if r == nil {
		return AlertCounts{}, errNotConfigured
	}
	orgs, err := s.alertOrganizations(ctx, c, org, rbac.PermPatchView)
	if err != nil {
		return AlertCounts{}, err
	}
	var out AlertCounts
	var whole []uuid.UUID
	for _, o := range orgs {
		if c.Can(rbac.PermPatchView, rbac.Org(o.id)) {
			whole = append(whole, o.ep)
			continue
		}
		p, err := cl.Alerts(s.as(ctx, c, RoleReadOnly, o.ep), AlertFilter{Status: "unresolved", OrganizationID: o.ep}, 1, PageSize)
		if err != nil {
			s.noteError(err)
			return AlertCounts{}, epError(err)
		}
		out.Capped = out.Capped || p.TotalCount > len(p.Items)
		views, err := s.alertViews(ctx, c, []reportOrg{o}, p.Items)
		if err != nil {
			return AlertCounts{}, err
		}
		for _, v := range views {
			out.count(v.Status, v.Severity)
		}
	}
	if len(whole) > 0 {
		sum, err := cl.AlertSummary(s.as(ctx, c, RoleReadOnly, whole...))
		if err != nil {
			s.noteError(err)
			return AlertCounts{}, epError(err)
		}
		out.Open += sum.Open
		out.Acknowledged += sum.Acknowledged
		out.Critical += sum.Critical
		out.Warning += sum.Warning
		out.Info += sum.Info
	}
	return out, nil
}

func (a *AlertCounts) count(status, severity string) {
	if status == "Acknowledged" {
		a.Acknowledged++
	} else {
		a.Open++
	}
	switch severity {
	case "Critical":
		a.Critical++
	case "Warning":
		a.Warning++
	default:
		a.Info++
	}
}

// AcknowledgeAlerts acknowledges the open alerts among ids that the caller
// may manage the patching of (a device's, or the whole organization's), and
// says how many it acknowledged. Alerts already acknowledged or resolved,
// and those the caller may not manage, are left as they are.
func (s *Service) AcknowledgeAlerts(ctx context.Context, c access.Caller, ids []uuid.UUID) (int, error) {
	if !c.CanAnywhere(rbac.PermPatchManage) {
		return 0, apperr.Forbidden()
	}
	ids = dedupe(ids)
	if len(ids) == 0 || len(ids) > maxAcknowledge {
		return 0, apperr.Invalid("alertIds", "Choose 1 to 200 alerts.")
	}
	_, cl, err := s.operable(ctx)
	if err != nil {
		return 0, err
	}
	orgs, err := s.alertOrganizations(ctx, c, uuid.Nil, rbac.PermPatchManage)
	if err != nil {
		return 0, err
	}
	// EasyPatch reads alerts by organization only, so EasyRMM finds those
	// asked for among each organization's open alerts.
	want := map[uuid.UUID]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var found []Alert
	for _, o := range orgs {
		for page := 1; page <= ackPages && len(want) > 0; page++ {
			p, err := cl.Alerts(s.as(ctx, c, RoleReadOnly, o.ep), AlertFilter{Status: "open", OrganizationID: o.ep}, page, PageSize)
			if err != nil {
				s.noteError(err)
				return 0, epError(err)
			}
			for _, a := range p.Items {
				if want[a.ID] {
					found = append(found, a)
					delete(want, a.ID)
				}
			}
			if page*PageSize >= p.TotalCount {
				break
			}
		}
	}
	views, err := s.alertViews(ctx, c, orgs, found)
	if err != nil {
		return 0, err
	}
	views = slices.DeleteFunc(views, func(v AlertView) bool { return !v.CanAcknowledge })
	if len(views) == 0 {
		return 0, nil
	}
	var chosen, engineOrgs []uuid.UUID
	for _, v := range views {
		chosen = append(chosen, v.ID)
		engineOrgs = append(engineOrgs, v.Alert.OrganizationID)
	}
	n, err := cl.AcknowledgeAlerts(s.as(ctx, c, RoleAdmin, engineOrgs...), chosen)
	if err != nil {
		s.noteError(err)
		return 0, epError(err)
	}
	return n, s.record(ctx, acknowledgeEvents(c, views))
}

// acknowledgeEvents records acknowledging: one event for each device, and
// one for each organization's own alerts, so that each is in its auditors'
// view.
func acknowledgeEvents(c access.Caller, views []AlertView) []audit.Event {
	type key struct{ org, device uuid.UUID }
	groups := map[key][]AlertView{}
	var order []key
	for _, v := range views {
		k := key{v.OrganizationID, idOf(v.DeviceID)}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], v)
	}
	events := make([]audit.Event, 0, len(order))
	for _, k := range order {
		list := groups[k]
		titles := make([]string, 0, min(len(list), 20))
		for _, v := range list[:min(len(list), 20)] {
			titles = append(titles, cut(v.Title, 200))
		}
		e := audit.Event{Actor: c.Actor, Action: "patch.alert_acknowledge", OrganizationID: k.org, TargetType: "easypatch_alert",
			Outcome: audit.Success, Details: map[string]any{"alerts": len(list), "titles": titles}}
		if k.device != uuid.Nil {
			e.SiteID, e.DeviceID, e.TargetType, e.TargetID = list[0].siteID, k.device, "device", k.device.String()
			e.Details["device"] = list[0].DeviceName
		} else if len(list) == 1 {
			e.TargetID = list[0].ID.String()
		}
		events = append(events, e)
	}
	return events
}
