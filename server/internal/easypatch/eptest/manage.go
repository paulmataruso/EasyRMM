package eptest

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Organizations and sites as EasyPatch keeps them (ADR-0040):
// names unique case-sensitively, archived ones included; archiving keeps
// the record and frees nothing; updates replace every field they carry.

// OrgInfo is an EasyPatch organization.
type OrgInfo struct {
	ID          uuid.UUID
	Name        string
	TimeZone    string
	Description *string
	Notes       *string
	Active      bool
	ArchivedAt  *time.Time
}

// SiteInfo is an EasyPatch site.
type SiteInfo struct {
	ID, Org     uuid.UUID
	Name        string
	TimeZone    string
	Description *string
	Address     *string
	Active      bool
	ArchivedAt  *time.Time
}

// Organizations lists the organizations, archived ones too, oldest first.
func (s *Server) Organizations() []OrgInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]OrgInfo, 0, len(s.orgs))
	for _, o := range s.orgs {
		out = append(out, *o)
	}
	return out
}

// Sites lists every organization's sites, archived ones too, oldest first.
func (s *Server) Sites() []SiteInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SiteInfo, 0, len(s.sites))
	for _, x := range s.sites {
		out = append(out, *x)
	}
	return out
}

func (s *Server) org(id uuid.UUID) *OrgInfo {
	i := slices.IndexFunc(s.orgs, func(o *OrgInfo) bool { return o.ID == id })
	if i < 0 {
		return nil
	}
	return s.orgs[i]
}

func (s *Server) site(id uuid.UUID) *SiteInfo {
	i := slices.IndexFunc(s.sites, func(x *SiteInfo) bool { return x.ID == id })
	if i < 0 {
		return nil
	}
	return s.sites[i]
}

func (s *Server) orgSummary(o *OrgInfo) map[string]any {
	sites, endpoints := 0, 0
	for _, x := range s.sites {
		if x.Org == o.ID && x.Active {
			sites++
		}
	}
	for _, e := range s.endpoints {
		if e.Org == o.ID && e.Status == "Active" {
			endpoints++
		}
	}
	return map[string]any{"id": o.ID, "name": o.Name, "description": o.Description, "timeZone": o.TimeZone, "isActive": o.Active,
		"siteCount": sites, "endpointCount": endpoints}
}

func (s *Server) orgDetail(o *OrgInfo) map[string]any {
	sites := []map[string]any{}
	for _, x := range s.sites {
		if x.Org == o.ID {
			sites = append(sites, s.siteDTO(x))
		}
	}
	return map[string]any{"id": o.ID, "name": o.Name, "description": o.Description, "contactName": nil, "contactEmail": nil,
		"notes": o.Notes, "timeZone": o.TimeZone, "isActive": o.Active, "createdAt": "2026-11-02T10:00:00+00:00",
		"updatedAt": "2026-11-02T10:00:00+00:00", "archivedAt": o.ArchivedAt, "sites": sites, "tags": s.tagRefs(o.ID, "")}
}

func (s *Server) siteDTO(x *SiteInfo) map[string]any {
	name := ""
	if o := s.org(x.Org); o != nil {
		name = o.Name
	}
	count := 0
	for _, e := range s.endpoints {
		if e.Site != nil && *e.Site == x.ID && e.Status == "Active" {
			count++
		}
	}
	return map[string]any{"id": x.ID, "organizationId": x.Org, "organizationName": name, "name": x.Name, "description": x.Description,
		"address": x.Address, "timeZone": x.TimeZone, "isActive": x.Active, "endpointCount": count, "rebootPendingCount": 0,
		"createdAt": "2026-11-02T10:00:00+00:00", "archivedAt": x.ArchivedAt, "tags": s.tagRefs(x.ID, "")}
}

// fields answers 400 validation_failed with EasyPatch's errors map.
func fields(w http.ResponseWriter, errs map[string]string) bool {
	if len(errs) == 0 {
		return false
	}
	m := map[string][]string{}
	var detail []string
	for k, v := range errs {
		m[k] = []string{v}
		detail = append(detail, k+": "+v)
	}
	slices.Sort(detail)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusBadRequest)
	_ = jsonEncode(w, map[string]any{"type": "https://easypatch.dev/problems/validation_failed", "title": "Validation failed",
		"status": 400, "detail": strings.Join(detail, "; "), "code": "validation_failed", "errors": m})
	return true
}

// nameAndZone reads and checks a name and time zone the way EasyPatch's
// validation does. A missing time zone is "" (keep or default).
func nameAndZone(body map[string]any) (string, string, map[string]string) {
	errs := map[string]string{}
	name, _ := body["name"].(string)
	if strings.TrimSpace(name) == "" {
		errs["name"] = "Name is required."
	} else if len(name) > 200 {
		errs["name"] = "Name must be at most 200 characters."
	}
	tz := ""
	if v, ok := body["timeZone"]; ok && v != nil {
		tz, _ = v.(string)
		if _, err := time.LoadLocation(tz); err != nil || tz == "" || tz == "Local" {
			errs["timeZone"] = "Use an IANA name such as Europe/London."
		}
	}
	return strings.TrimSpace(name), tz, errs
}

func optional(body map[string]any, key string) *string {
	v, ok := body[key].(string)
	if !ok || strings.TrimSpace(v) == "" {
		return nil
	}
	v = strings.TrimSpace(v)
	return &v
}

// serveOrganizations answers /api/v1/organizations/... other than the
// organization lists.
func (s *Server) serveOrganizations(w http.ResponseWriter, r *http.Request, parts []string, body map[string]any) {
	write := r.Method != http.MethodGet
	if write && s.readOnlyCall {
		problem(w, 403, "forbidden", "You do not have permission.")
		return
	}
	switch {
	case len(parts) == 1 && r.Method == http.MethodGet:
		list := []map[string]any{}
		all := r.URL.Query().Get("includeArchived") == "true"
		for _, o := range s.sortedOrgs() {
			if o.Active || all {
				list = append(list, s.orgSummary(o))
			}
		}
		reply(w, 200, list)
	case len(parts) == 1 && r.Method == http.MethodPost:
		if !s.unrestricted() {
			problem(w, 403, "forbidden", "Only administrators with access to all organizations can create organizations.")
			return
		}
		name, tz, errs := nameAndZone(body)
		if fields(w, errs) {
			return
		}
		if slices.ContainsFunc(s.orgs, func(o *OrgInfo) bool { return o.Name == name }) {
			problem(w, 409, "conflict", "A record with the same unique value already exists.")
			return
		}
		if tz == "" {
			tz = "UTC"
		}
		o := &OrgInfo{ID: uuid.New(), Name: name, TimeZone: tz, Description: optional(body, "description"), Notes: optional(body, "notes"), Active: true}
		s.orgs = append(s.orgs, o)
		reply(w, 201, s.orgDetail(o))
	case len(parts) >= 2:
		id, _ := uuid.Parse(parts[1])
		o := s.org(id)
		if o == nil {
			problem(w, 404, "not_found", "Organization not found.")
			return
		}
		sub := strings.Join(parts[2:], "/")
		switch {
		case sub == "" && r.Method == http.MethodGet:
			reply(w, 200, s.orgDetail(o))
		case sub == "" && r.Method == http.MethodPut:
			name, tz, errs := nameAndZone(body)
			if fields(w, errs) {
				return
			}
			if slices.ContainsFunc(s.orgs, func(x *OrgInfo) bool { return x.ID != o.ID && x.Name == name }) {
				problem(w, 409, "conflict", "A record with the same unique value already exists.")
				return
			}
			o.Name, o.Description, o.Notes = name, optional(body, "description"), optional(body, "notes")
			if tz != "" {
				o.TimeZone = tz
			}
			for _, e := range s.endpoints {
				if e.Org == o.ID {
					e.OrgName = name
				}
			}
			reply(w, 200, s.orgDetail(o))
		case sub == "archive" && r.Method == http.MethodPost:
			now := time.Now().UTC()
			o.Active, o.ArchivedAt = false, &now
			reply(w, 200, s.orgDetail(o))
		case sub == "restore" && r.Method == http.MethodPost:
			o.Active, o.ArchivedAt = true, nil
			reply(w, 200, s.orgDetail(o))
		case sub == "sites" && r.Method == http.MethodGet:
			list := []map[string]any{}
			all := r.URL.Query().Get("includeArchived") == "true"
			for _, x := range s.sites {
				if x.Org == o.ID && (x.Active || all) {
					list = append(list, s.siteDTO(x))
				}
			}
			reply(w, 200, list)
		case sub == "sites" && r.Method == http.MethodPost:
			name, tz, errs := nameAndZone(body)
			if fields(w, errs) {
				return
			}
			if slices.ContainsFunc(s.sites, func(x *SiteInfo) bool { return x.Org == o.ID && x.Name == name }) {
				problem(w, 409, "conflict", "A record with the same unique value already exists.")
				return
			}
			if tz == "" {
				tz = o.TimeZone
			}
			x := &SiteInfo{ID: uuid.New(), Org: o.ID, Name: name, TimeZone: tz, Description: optional(body, "description"),
				Address: optional(body, "address"), Active: true}
			s.sites = append(s.sites, x)
			reply(w, 201, s.siteDTO(x))
		case sub == "restart-pending" && r.Method == http.MethodGet:
			s.restartPending(w, parts[1])
		default:
			problem(w, 404, "not_found", "No such route: "+r.URL.Path)
		}
	default:
		problem(w, 404, "not_found", "No such route: "+r.URL.Path)
	}
}

// serveSite answers /api/v1/sites/{id}[/archive].
func (s *Server) serveSite(w http.ResponseWriter, r *http.Request, parts []string, body map[string]any) {
	if r.Method != http.MethodGet && s.readOnlyCall {
		problem(w, 403, "forbidden", "You do not have permission.")
		return
	}
	id, _ := uuid.Parse(parts[1])
	x := s.site(id)
	if x == nil {
		problem(w, 404, "not_found", "Site not found.")
		return
	}
	sub := strings.Join(parts[2:], "/")
	switch {
	case sub == "" && r.Method == http.MethodGet:
		reply(w, 200, s.siteDTO(x))
	case sub == "" && r.Method == http.MethodPut:
		name, tz, errs := nameAndZone(body)
		if fields(w, errs) {
			return
		}
		if slices.ContainsFunc(s.sites, func(y *SiteInfo) bool { return y.ID != x.ID && y.Org == x.Org && y.Name == name }) {
			problem(w, 409, "conflict", "A record with the same unique value already exists.")
			return
		}
		x.Name, x.Description, x.Address = name, optional(body, "description"), optional(body, "address")
		if tz != "" {
			x.TimeZone = tz
		}
		for _, e := range s.endpoints {
			if e.Site != nil && *e.Site == x.ID {
				e.SiteName = name
			}
		}
		reply(w, 200, s.siteDTO(x))
	case sub == "archive" && r.Method == http.MethodPost:
		now := time.Now().UTC()
		x.Active, x.ArchivedAt = false, &now
		reply(w, 200, s.siteDTO(x))
	case sub == "restore" && r.Method == http.MethodPost:
		x.Active, x.ArchivedAt = true, nil
		reply(w, 200, s.siteDTO(x))
	default:
		problem(w, 404, "not_found", "No such route: "+r.URL.Path)
	}
}

// updateEndpoint answers PUT /api/v1/endpoints/{id}: every field replaced,
// a site only of the endpoint's own organization.
func (s *Server) updateEndpoint(w http.ResponseWriter, e *Endpoint, body map[string]any) {
	var site *SiteInfo
	if v, ok := body["siteId"].(string); ok {
		id, err := uuid.Parse(v)
		if site = s.site(id); err != nil || site == nil || site.Org != e.Org {
			fields(w, map[string]string{"siteId": "The site does not belong to this endpoint's organization."})
			return
		}
	}
	if site == nil {
		e.Site, e.SiteName = nil, ""
	} else {
		e.Site, e.SiteName = &site.ID, site.Name
	}
	e.Notes = optional(body, "notes")
	if v, ok := body["esuOverride"].(string); ok {
		e.Esu = v
	}
	reply(w, 200, e.detail())
}

// uninstall answers POST /api/v1/endpoints/{id}/uninstall-agent. The agent
// removes itself and unenrolls when the job completes (SetJobStatus).
func (s *Server) uninstall(w http.ResponseWriter, e *Endpoint) {
	if e.Status != "Active" {
		problem(w, 409, "endpoint_not_active", fmt.Sprintf("%s is not active.", e.Hostname))
		return
	}
	if e.CannotUninstall {
		problem(w, 409, "agent_upgrade_required", fmt.Sprintf("The EasyPatch agent on %s cannot uninstall itself.", e.Hostname))
		return
	}
	for _, j := range s.jobs {
		if j.Endpoint == e.ID && j.Type == "UninstallAgent" && (j.Status == "Queued" || j.Status == "Running") {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusConflict)
			_ = jsonEncode(w, map[string]any{"status": 409, "code": "duplicate_job", "detail": "An uninstall is already queued.", "existingJobId": j.ID})
			return
		}
	}
	j := s.newJob(e, "UninstallAgent", nil)
	w.Header().Set("Location", "/api/v1/jobs/"+j.ID.String())
	reply(w, 202, j.summary())
}

// revoke answers POST /api/v1/endpoints/{id}/revoke: credentials revoked,
// open jobs ended.
func (s *Server) revoke(w http.ResponseWriter, e *Endpoint) {
	e.Status, e.Revoked = "Revoked", true
	for _, j := range s.jobs {
		if j.Endpoint == e.ID && (j.Status == "Queued" || j.Status == "Running") {
			j.Status = StatusCanceled
		}
	}
	reply(w, 200, e.detail())
}

func (s *Server) sortedOrgs() []*OrgInfo {
	list := slices.Clone(s.orgs)
	slices.SortStableFunc(list, func(a, b *OrgInfo) int { return strings.Compare(a.Name, b.Name) })
	return list
}

// unrestricted is whether the request's statement names all organizations.
func (s *Server) unrestricted() bool {
	st := s.requests[len(s.requests)-1].Statement
	return st != nil && st.AllOrganizations
}

// EndpointState is an endpoint as it is now.
func (s *Server) EndpointState(id uuid.UUID) (Endpoint, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.endpoints[id]
	if e == nil {
		return Endpoint{}, false
	}
	return *e, true
}

// ChangeOrganization changes an organization, as someone in EasyPatch's own
// console would.
func (s *Server) ChangeOrganization(id uuid.UUID, fn func(o *OrgInfo)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if o := s.org(id); o != nil {
		fn(o)
	}
}

// DeleteOrganization deletes an organization and its sites, as EasyPatch
// deletes one without endpoints.
func (s *Server) DeleteOrganization(id uuid.UUID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.orgs = slices.DeleteFunc(s.orgs, func(o *OrgInfo) bool { return o.ID == id })
	s.sites = slices.DeleteFunc(s.sites, func(x *SiteInfo) bool { return x.Org == id })
}

// Changes counts the calls that could have changed something: all but
// reads.
func (s *Server) Changes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.requests {
		if r.Method != http.MethodGet {
			n++
		}
	}
	return n
}

// ChangeSite changes a site behind EasyRMM's back, as an imported server's
// settings or a direct database edit would.
func (s *Server) ChangeSite(id uuid.UUID, fn func(x *SiteInfo)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if x := s.site(id); x != nil {
		fn(x)
	}
}

// DeleteSite deletes a site, as EasyPatch deletes one without endpoints.
func (s *Server) DeleteSite(id uuid.UUID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sites = slices.DeleteFunc(s.sites, func(x *SiteInfo) bool { return x.ID == id })
}
