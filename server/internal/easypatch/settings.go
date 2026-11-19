package easypatch

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Settings → Patching's server-wide views (one-product plan, C6): EasyPatch's
// server settings with its vulnerability feeds, the operating systems'
// end-of-servicing dates, the agent packages it hosts and its audit log.
//
// Those who configure patching anywhere (patch.configure) see the settings,
// lifecycle and packages, which shape every organization's patching. They
// are server-wide, so only super administrators change them, with
// SuperAdmin statements. The audit log needs audit.view
// and patch.view over the organizations it shows; a super administrator
// also sees the server-wide entries.

// SettingsView is EasyPatch's server settings as Settings → Patching shows
// them.
type SettingsView struct {
	Settings ServerSettings      `json:"settings"`
	Feeds    []VulnerabilityFeed `json:"feeds"`
	// Version is the EasyPatch server's.
	Version string `json:"version"`
	CanEdit bool   `json:"canEdit"`
}

// readServerWide checks that the caller may see the server-wide settings.
func (s *Service) readServerWide(ctx context.Context, c access.Caller) (*connRow, *Client, error) {
	r, cl, err := s.conn(ctx)
	switch {
	case err != nil:
		return nil, nil, err
	case r == nil:
		return nil, nil, errNotConfigured
	case !c.CanAnywhere(rbac.PermPatchConfigure):
		return nil, nil, apperr.Forbidden()
	}
	return r, cl, nil
}

// changeServerWide checks that the caller may change them.
func (s *Service) changeServerWide(ctx context.Context, c access.Caller) (*Client, error) {
	_, cl, err := s.operable(ctx)
	switch {
	case err != nil:
		return nil, err
	case !c.CanGlobal(rbac.PermPatchConfigure):
		return nil, apperr.Forbidden()
	}
	return cl, nil
}

// ServerSettings reads EasyPatch's server settings and the state of its
// vulnerability feeds.
func (s *Service) ServerSettings(ctx context.Context, c access.Caller) (SettingsView, error) {
	r, cl, err := s.readServerWide(ctx, c)
	if err != nil {
		return SettingsView{}, err
	}
	rctx := s.as(ctx, c, RoleReadOnly)
	settings, err := cl.ServerSettings(rctx)
	if err != nil {
		s.noteError(err)
		return SettingsView{}, epError(err)
	}
	feeds, err := cl.VulnerabilityFeeds(rctx)
	if err != nil {
		s.noteError(err)
		return SettingsView{}, epError(err)
	}
	return SettingsView{Settings: settings, Feeds: orEmpty(feeds), Version: r.version, CanEdit: c.CanGlobal(rbac.PermPatchConfigure)}, nil
}

// settingRange is a server setting's bounds, as EasyPatch checks them.
type settingRange struct {
	field    string
	value    func(*ServerSettings) int
	min, max int
}

var settingRanges = []settingRange{
	{"globalMaxConcurrentInstalls", func(s *ServerSettings) int { return s.GlobalMaxConcurrentInstalls }, 1, 10_000},
	{"jobDefaultExpiryHours", func(s *ServerSettings) int { return s.JobDefaultExpiryHours }, 1, 24 * 90},
	{"runningJobTimeoutHours", func(s *ServerSettings) int { return s.RunningJobTimeoutHours }, 1, 168},
	{"waitingForRebootExpiryDays", func(s *ServerSettings) int { return s.WaitingForRebootExpiryDays }, 1, 365},
	{"deliveryLeaseMinutes", func(s *ServerSettings) int { return s.DeliveryLeaseMinutes }, 2, 120},
	{"maxDeliveryAttempts", func(s *ServerSettings) int { return s.MaxDeliveryAttempts }, 1, 50},
	{"offlineThresholdMinutes", func(s *ServerSettings) int { return s.OfflineThresholdMinutes }, 3, 1440},
	{"credentialLifetimeDays", func(s *ServerSettings) int { return s.CredentialLifetimeDays }, 30, 3650},
	{"credentialRotateBeforeDays", func(s *ServerSettings) int { return s.CredentialRotateBeforeDays }, 1, 180},
	{"retentionEventsDays", func(s *ServerSettings) int { return s.RetentionEventsDays }, 7, 3650},
	{"retentionAuditDays", func(s *ServerSettings) int { return s.RetentionAuditDays }, 30, 3650},
	{"retentionJobsDays", func(s *ServerSettings) int { return s.RetentionJobsDays }, 7, 3650},
	{"retentionScansDays", func(s *ServerSettings) int { return s.RetentionScansDays }, 7, 3650},
	{"retentionHistoryDays", func(s *ServerSettings) int { return s.RetentionHistoryDays }, 30, 3650},
	{"retentionReportsMonths", func(s *ServerSettings) int { return s.RetentionReportsMonths }, 1, 120},
	{"rolloutGuardMinFailedEndpoints", func(s *ServerSettings) int { return s.RolloutGuardMinFailedEndpoints }, 1, 1000},
	{"rolloutGuardFailurePercent", func(s *ServerSettings) int { return s.RolloutGuardFailurePercent }, 1, 100},
	{"rolloutGuardWindowDays", func(s *ServerSettings) int { return s.RolloutGuardWindowDays }, 1, 90},
}

// normalizeSettings checks server settings as EasyPatch does, field by
// field.
func normalizeSettings(in *ServerSettings) error {
	f := apperr.Fields{}
	for _, r := range settingRanges {
		v := r.value(in)
		f.Check(v >= r.min && v <= r.max, r.field, "Choose a value from "+itoa(r.min)+" to "+itoa(r.max)+".")
	}
	f.Check(in.CredentialRotateBeforeDays < in.CredentialLifetimeDays, "credentialRotateBeforeDays",
		"Rotate credentials before they expire: choose fewer days than their lifetime.")
	if in.ReportBrandName != nil {
		b := strings.TrimSpace(*in.ReportBrandName)
		f.Check(len([]rune(b)) <= 100 && !strings.ContainsFunc(b, unicode.IsControl), "reportBrandName",
			"Give at most 100 characters, without control characters.")
		in.ReportBrandName = &b
		if b == "" {
			in.ReportBrandName = nil
		}
	}
	return f.Err()
}

// settingsChanges lists, by field, the old and new value of each setting
// that differs.
func settingsChanges(before, after ServerSettings) map[string]any {
	var a, b map[string]any
	ab, _ := json.Marshal(before)
	bb, _ := json.Marshal(after)
	_ = json.Unmarshal(ab, &a)
	_ = json.Unmarshal(bb, &b)
	out := map[string]any{}
	for k, v := range b {
		if old := a[k]; !jsonEqual(old, v) {
			out[k] = map[string]any{"from": old, "to": v}
		}
	}
	return out
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// SetServerSettings changes EasyPatch's server settings, and keeps those
// EasyRMM does not show as they are.
func (s *Service) SetServerSettings(ctx context.Context, c access.Caller, in ServerSettings) (SettingsView, error) {
	cl, err := s.changeServerWide(ctx, c)
	if err != nil {
		return SettingsView{}, err
	}
	if err := normalizeSettings(&in); err != nil {
		return SettingsView{}, err
	}
	st := s.everywhere(ctx, c, RoleSuperAdmin)
	before, err := cl.ServerSettings(st)
	if err != nil {
		s.noteError(err)
		return SettingsView{}, epError(err)
	}
	changes := settingsChanges(before, in)
	if len(changes) > 0 {
		if _, err := cl.SetServerSettings(st, in); err != nil {
			s.noteError(err)
			return SettingsView{}, epError(err)
		}
		if err := s.record(ctx, []audit.Event{{Actor: c.Actor, Action: "patch.settings_update", TargetType: "easypatch_settings",
			TargetID: "server", Outcome: audit.Success, Details: map[string]any{"changes": changes}}}); err != nil {
			return SettingsView{}, err
		}
	}
	return s.ServerSettings(ctx, c)
}

// LifecycleList is the lifecycle entries, by product, newest build first.
type LifecycleList struct {
	Items   []LifecycleEntry `json:"items"`
	CanEdit bool             `json:"canEdit"`
}

// Lifecycle lists the operating systems' end-of-servicing dates.
func (s *Service) Lifecycle(ctx context.Context, c access.Caller) (LifecycleList, error) {
	_, cl, err := s.readServerWide(ctx, c)
	if err != nil {
		return LifecycleList{}, err
	}
	items, err := cl.Lifecycle(s.as(ctx, c, RoleReadOnly))
	if err != nil {
		s.noteError(err)
		return LifecycleList{}, epError(err)
	}
	slices.SortStableFunc(items, func(a, b LifecycleEntry) int {
		if c := strings.Compare(a.Product, b.Product); c != 0 {
			return c
		}
		if a.BuildNumber != b.BuildNumber {
			return b.BuildNumber - a.BuildNumber
		}
		return strings.Compare(a.EditionGroup, b.EditionGroup)
	})
	return LifecycleList{Items: orEmpty(items), CanEdit: c.CanGlobal(rbac.PermPatchConfigure)}, nil
}

// normalizeLifecycle checks a lifecycle entry as EasyPatch does.
func normalizeLifecycle(in *LifecycleInput) error {
	f := apperr.Fields{}
	text := func(field string, v *string, max int, label string) {
		*v = strings.TrimSpace(*v)
		f.Check(*v != "" && len([]rune(*v)) <= max, field, "Give "+label+" of 1 to "+itoa(max)+" characters.")
	}
	// EasyPatch's database keeps 64 characters of a product, though its
	// check allows 100.
	text("product", &in.Product, 64, "a product")
	text("editionGroup", &in.EditionGroup, 50, "an edition group")
	text("versionLabel", &in.VersionLabel, 50, "a version")
	f.Check(in.BuildNumber >= 1 && in.BuildNumber <= 1_000_000, "buildNumber", "Give a build number from 1 to 1,000,000.")
	eos, err := time.Parse(time.DateOnly, in.EndOfServicing)
	f.Check(err == nil, "endOfServicing", "Give the date servicing ends.")
	if in.EsuEndDate != nil && strings.TrimSpace(*in.EsuEndDate) == "" {
		in.EsuEndDate = nil
	}
	if in.EsuEndDate != nil {
		esu, err2 := time.Parse(time.DateOnly, *in.EsuEndDate)
		f.Check(err2 == nil, "esuEndDate", "Give a date, or leave it empty.")
		f.Check(err != nil || err2 != nil || !esu.Before(eos), "esuEndDate", "Extended security updates end on or after servicing ends.")
	}
	if in.Notes != nil {
		n := strings.TrimSpace(*in.Notes)
		f.Check(len([]rune(n)) <= 1000, "notes", "Keep notes to 1,000 characters.")
		in.Notes = &n
		if n == "" {
			in.Notes = nil
		}
	}
	return f.Err()
}

func lifecycleDetails(e LifecycleInput) map[string]any {
	d := map[string]any{"product": e.Product, "editionGroup": e.EditionGroup, "buildNumber": e.BuildNumber, "versionLabel": e.VersionLabel,
		"endOfServicing": e.EndOfServicing}
	if e.EsuEndDate != nil {
		d["esuEndDate"] = *e.EsuEndDate
	}
	return d
}

func (s *Service) recordLifecycle(ctx context.Context, c access.Caller, action string, id uuid.UUID, details map[string]any) error {
	return s.record(ctx, []audit.Event{{Actor: c.Actor, Action: action, TargetType: "easypatch_lifecycle", TargetID: id.String(),
		Outcome: audit.Success, Details: details}})
}

// errLifecycleExists is EasyPatch refusing a second entry for a product,
// edition group and build.
var errLifecycleExists = apperr.Invalid("buildNumber", "There is already an entry for this product, edition group and build.")

func lifecycleError(err error) error {
	if IsStatus(err, http.StatusConflict) {
		return errLifecycleExists
	}
	return epError(err)
}

// CreateLifecycle adds a lifecycle entry.
func (s *Service) CreateLifecycle(ctx context.Context, c access.Caller, in LifecycleInput) (LifecycleEntry, error) {
	cl, err := s.changeServerWide(ctx, c)
	if err != nil {
		return LifecycleEntry{}, err
	}
	if err := normalizeLifecycle(&in); err != nil {
		return LifecycleEntry{}, err
	}
	e, err := cl.CreateLifecycle(s.everywhere(ctx, c, RoleSuperAdmin), in)
	if err != nil {
		s.noteError(err)
		return LifecycleEntry{}, lifecycleError(err)
	}
	s.fleet.clear()
	return e, s.recordLifecycle(ctx, c, "patch.lifecycle_create", e.ID, lifecycleDetails(e.LifecycleInput))
}

// UpdateLifecycle changes a lifecycle entry.
func (s *Service) UpdateLifecycle(ctx context.Context, c access.Caller, id uuid.UUID, in LifecycleInput) (LifecycleEntry, error) {
	cl, err := s.changeServerWide(ctx, c)
	if err != nil {
		return LifecycleEntry{}, err
	}
	if err := normalizeLifecycle(&in); err != nil {
		return LifecycleEntry{}, err
	}
	e, err := cl.UpdateLifecycle(s.everywhere(ctx, c, RoleSuperAdmin), id, in)
	if err != nil {
		s.noteError(err)
		return LifecycleEntry{}, lifecycleError(err)
	}
	s.fleet.clear()
	return e, s.recordLifecycle(ctx, c, "patch.lifecycle_update", e.ID, lifecycleDetails(e.LifecycleInput))
}

// DeleteLifecycle deletes a lifecycle entry: endpoints on its build show an
// unknown support status until another matches.
func (s *Service) DeleteLifecycle(ctx context.Context, c access.Caller, id uuid.UUID) error {
	cl, err := s.changeServerWide(ctx, c)
	if err != nil {
		return err
	}
	st := s.everywhere(ctx, c, RoleSuperAdmin)
	items, err := cl.Lifecycle(st)
	if err != nil {
		s.noteError(err)
		return epError(err)
	}
	i := slices.IndexFunc(items, func(e LifecycleEntry) bool { return e.ID == id })
	if i < 0 {
		return apperr.NotFound()
	}
	if err := cl.DeleteLifecycle(st, id); err != nil {
		s.noteError(err)
		return epError(err)
	}
	s.fleet.clear()
	return s.recordLifecycle(ctx, c, "patch.lifecycle_delete", id, lifecycleDetails(items[i].LifecycleInput))
}

// PackageView is an agent package EasyPatch hosts, with where to download
// it.
type PackageView struct {
	AgentPackage
	// URL downloads the package, from EasyRMM's own address.
	URL string `json:"url"`
}

// AgentPackageList lists the EasyPatch agent packages, newest first.
func (s *Service) AgentPackageList(ctx context.Context, c access.Caller) ([]PackageView, error) {
	_, cl, err := s.readServerWide(ctx, c)
	if err != nil {
		return nil, err
	}
	pkgs, err := cl.AgentPackages(s.as(ctx, c, RoleReadOnly))
	if err != nil {
		s.noteError(err)
		return nil, epError(err)
	}
	out := make([]PackageView, 0, len(pkgs))
	for _, p := range pkgs {
		v := PackageView{AgentPackage: p}
		if strings.HasPrefix(p.DownloadURL, "/downloads/agent/") {
			v.URL = p.DownloadURL
		}
		out = append(out, v)
	}
	return out, nil
}

// AuditAreas are the areas EasyPatch's audit log filters on: a prefix of
// its actions' names.
var AuditAreas = []string{"organization.", "site.", "policy.", "tag.", "endpoint.", "job.", "update.", "report", "alert", "notifications.",
	"settings.", "lifecycle.", "auth.", "user.", "api_token.", "sso."}

// auditPageSize is how many audit entries a page shows.
const auditPageSize = 50

// AuditQuery narrows EasyPatch's audit log: an area (one of AuditAreas)
// and a period, From included and To not.
type AuditQuery struct {
	OrganizationID uuid.UUID
	Area           string
	From, To       *time.Time
	Page           int
}

// AuditEntry is an entry of EasyPatch's audit log, in EasyRMM's terms.
type AuditEntry struct {
	ID        int64     `json:"id"`
	CreatedAt time.Time `json:"createdAt"`
	// Actor is who acted: an EasyRMM user's name (Via "easyrmm"), an
	// EasyPatch user or API token from before an import (Via "easypatch"),
	// or nobody: EasyPatch itself (Via "system").
	Actor      string `json:"actor"`
	Via        string `json:"via"`
	Action     string `json:"action"`
	TargetType string `json:"targetType"`
	TargetID   string `json:"targetId"`
	// The EasyRMM organization and device the entry concerns, when EasyRMM
	// links them and the caller sees them.
	OrganizationID   *uuid.UUID `json:"organizationId,omitempty"`
	OrganizationName string     `json:"organizationName,omitempty"`
	DeviceID         *uuid.UUID `json:"deviceId,omitempty"`
	DeviceName       string     `json:"deviceName,omitempty"`
	Details          string     `json:"details"`
	IPAddress        string     `json:"ipAddress"`
}

// AuditPage is a page of EasyPatch's audit log. Everything says it includes
// the entries of no organization (server settings, sign-ins, EasyPatch's own
// tasks), which only those who see audit and patching everywhere see.
type AuditPage struct {
	Items      []AuditEntry `json:"items"`
	Page       int          `json:"page"`
	PageSize   int          `json:"pageSize"`
	TotalCount int          `json:"totalCount"`
	Everything bool         `json:"everything"`
}

func (q *AuditQuery) check() error {
	f := apperr.Fields{}
	f.Check(q.From == nil || q.To == nil || q.From.Before(*q.To), "to", "End on or after the first day.")
	f.Check(q.Area == "" || slices.Contains(AuditAreas, q.Area), "area", "Choose one of the areas.")
	return f.Err()
}

// AuditLog reads a page of EasyPatch's audit log: the entries of the linked
// organizations where the caller holds audit.view and patch.view over the
// whole organization, and for someone who holds both everywhere, every
// entry.
func (s *Service) AuditLog(ctx context.Context, c access.Caller, q AuditQuery) (AuditPage, error) {
	r, cl, err := s.conn(ctx)
	switch {
	case err != nil:
		return AuditPage{}, err
	case r == nil:
		return AuditPage{}, errNotConfigured
	case !c.CanAnywhere(rbac.PermAuditView) || !c.CanAnywhere(rbac.PermPatchView):
		return AuditPage{}, apperr.Forbidden()
	}
	if err := q.check(); err != nil {
		return AuditPage{}, err
	}
	everything := c.CanGlobal(rbac.PermAuditView) && c.CanGlobal(rbac.PermPatchView)
	orgs, err := s.wholeOrganizations(ctx, c, q.OrganizationID, rbac.PermAuditView, rbac.PermPatchView)
	if err != nil {
		return AuditPage{}, err
	}
	page := max(q.Page, 1)
	empty := AuditPage{Items: []AuditEntry{}, Page: page, PageSize: auditPageSize, Everything: everything && q.OrganizationID == uuid.Nil}
	if q.OrganizationID != uuid.Nil && len(orgs) == 0 {
		return AuditPage{}, apperr.NotFound()
	}
	if !everything && len(orgs) == 0 {
		return empty, nil
	}
	f := AuditFilter{Action: q.Area, From: q.From, To: q.To}
	var rctx context.Context
	if everything {
		rctx = s.everywhere(ctx, c, RoleAdmin)
	} else {
		eps := make([]uuid.UUID, 0, len(orgs))
		for _, o := range orgs {
			eps = append(eps, o.ep)
		}
		rctx = s.as(ctx, c, RoleAdmin, eps...)
	}
	if q.OrganizationID != uuid.Nil {
		f.OrganizationID = &orgs[0].ep
	}
	p, err := cl.AuditLogs(rctx, f, page, auditPageSize)
	if err != nil {
		s.noteError(err)
		return AuditPage{}, epError(err)
	}
	byEP := map[uuid.UUID]reportOrg{}
	for _, o := range orgs {
		byEP[o.ep] = o
	}
	var endpoints []uuid.UUID
	for _, a := range p.Items {
		if a.EndpointID != nil {
			endpoints = append(endpoints, *a.EndpointID)
		}
	}
	devices, err := s.linkedDevices(ctx, c, endpoints)
	if err != nil {
		return AuditPage{}, err
	}
	out := empty
	out.TotalCount = p.TotalCount
	for _, a := range p.Items {
		e := AuditEntry{ID: a.ID, CreatedAt: a.CreatedAt, Action: a.Action, TargetType: a.TargetType, TargetID: a.TargetID,
			Details: a.Details, IPAddress: a.IPAddress}
		e.Actor, e.Via = auditActor(a.Username)
		if a.OrganizationID != nil {
			if o, ok := byEP[*a.OrganizationID]; ok {
				e.OrganizationID, e.OrganizationName = &o.id, o.name
			}
		}
		if a.EndpointID != nil {
			if d, ok := devices[*a.EndpointID]; ok {
				e.DeviceID, e.DeviceName = &d.id, d.name
			}
		}
		out.Items = append(out.Items, e)
	}
	return out, nil
}

// auditActor names who an EasyPatch audit entry says acted.
func auditActor(username string) (string, string) {
	switch {
	case username == "":
		return "EasyPatch", "system"
	case strings.HasPrefix(username, "easyrmm:"):
		return strings.TrimPrefix(username, "easyrmm:"), "easyrmm"
	}
	return username, "easypatch"
}

// wholeOrganizations lists the linked organizations (or the one asked for)
// where the caller holds every permission over the whole organization.
func (s *Service) wholeOrganizations(ctx context.Context, c access.Caller, org uuid.UUID, perms ...rbac.Permission) ([]reportOrg, error) {
	all, err := s.linkedOrganizations(ctx, c, org)
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, o := range all {
		if !slices.ContainsFunc(perms, func(p rbac.Permission) bool { return !c.Can(p, rbac.Org(o.id)) }) {
			out = append(out, o)
		}
	}
	return out, nil
}

func itoa(n int) string { return strconv.Itoa(n) }
