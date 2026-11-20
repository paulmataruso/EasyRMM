package eptest

// Policies at every level and tags, as the engine serves them: a level
// with no policy answers with every value null; a policy is replaced whole;
// the global policy is always complete; tags and tag policies are for super
// administrators, and assigning tags for administrators of every
// organization.

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// TagInfo is an EasyPatch tag.
type TagInfo struct {
	ID          uuid.UUID
	Name, Color string
	Description *string
	Priority    int
}

// The levels of a policy, as SetPolicy and StoredPolicy name them.
const (
	ScopeGlobal       = "Global"
	ScopeOrganization = "Organization"
	ScopeSite         = "Site"
	ScopeEndpoint     = "Endpoint"
	ScopeTag          = "Tag"
)

var policyKeys = []string{"checkInIntervalSeconds", "scanIntervalMinutes", "inventoryIntervalMinutes", "jitterPercent", "allowedCategories",
	"includeOptional", "excludedKbs", "acceptEulas", "autoInstallEnabled", "maintenanceDays", "maintenanceStart", "maintenanceDurationMinutes",
	"scanStaleAfterHours", "maxConcurrentInstallsPerSite", "trayIconEnabled", "installNotificationsEnabled", "restartSchedule", "windowsUpdate",
	"agentAutoUpdateEnabled", "installDelayDays", "securityInstallDelayDays", "knownExploitedSkipsDelay", "applicationUpdates", "preDownloadHours"}

// globalDefaults is EasyPatch's built-in global policy (PolicyDefaults).
func globalDefaults() map[string]any {
	return map[string]any{"checkInIntervalSeconds": 60, "scanIntervalMinutes": 360, "inventoryIntervalMinutes": 1440, "jitterPercent": 10,
		"allowedCategories": []any{"Security", "Critical", "Cumulative", "Definition", "ServicingStack", "DotNet", "Other"},
		"includeOptional":   false, "excludedKbs": []any{}, "acceptEulas": true, "autoInstallEnabled": false, "installDelayDays": 0,
		"securityInstallDelayDays": 0, "knownExploitedSkipsDelay": true, "maintenanceDays": []any{}, "maintenanceStart": "02:00",
		"maintenanceDurationMinutes": 180, "preDownloadHours": 0, "scanStaleAfterHours": 48, "maxConcurrentInstallsPerSite": 10,
		"trayIconEnabled": true, "installNotificationsEnabled": true, "agentAutoUpdateEnabled": true,
		"id": "00000000-0000-0000-0000-000000000001"}
}

func policyKey(scope string, id uuid.UUID) string { return scope + ":" + id.String() }

// SetPolicy stores a level's policy (id is uuid.Nil for the global one);
// nil removes it.
func (s *Server) SetPolicy(scope string, id uuid.UUID, values map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.policies == nil {
		s.policies = map[string]map[string]any{}
	}
	if values == nil {
		delete(s.policies, policyKey(scope, id))
		return
	}
	v := map[string]any{"id": uuid.NewString(), "updatedAt": time.Now().UTC()}
	for k, x := range values {
		v[k] = x
	}
	s.policies[policyKey(scope, id)] = v
}

// StoredPolicy is a level's policy as EasyPatch keeps it; nil when it has
// none.
func (s *Server) StoredPolicy(scope string, id uuid.UUID) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.policies[policyKey(scope, id)]
}

// AddTag adds a tag.
func (s *Server) AddTag(name, color string, priority int) uuid.UUID {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := &TagInfo{ID: uuid.New(), Name: name, Color: color, Priority: priority}
	s.tags = append(s.tags, t)
	return t.ID
}

// Tags lists the tags.
func (s *Server) Tags() []TagInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []TagInfo{}
	for _, t := range s.tags {
		out = append(out, *t)
	}
	return out
}

// SetTagsOf gives an organization, site or endpoint its own tags.
func (s *Server) SetTagsOf(id uuid.UUID, tags ...uuid.UUID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tagged == nil {
		s.tagged = map[uuid.UUID][]uuid.UUID{}
	}
	s.tagged[id] = tags
}

// TagsOf lists an organization's, site's or endpoint's own tags.
func (s *Server) TagsOf(id uuid.UUID) []uuid.UUID {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.tagged[id])
}

// superAdmin says the call may do what EasyPatch keeps to super
// administrators.
func (s *Server) superAdmin() bool {
	return s.role() == "SuperAdmin"
}

func (s *Server) findTag(id uuid.UUID) *TagInfo {
	i := slices.IndexFunc(s.tags, func(t *TagInfo) bool { return t.ID == id })
	if i < 0 {
		return nil
	}
	return s.tags[i]
}

func (s *Server) tagRefs(id uuid.UUID, from string) []map[string]any {
	out := []map[string]any{}
	for _, tid := range s.tagged[id] {
		if t := s.findTag(tid); t != nil {
			out = append(out, map[string]any{"id": t.ID, "name": t.Name, "color": t.Color, "inheritedFrom": nullable(from)})
		}
	}
	return out
}

// endpointTags are an endpoint's tags: its own, then its site's, then its
// organization's, each once.
func (s *Server) endpointTags(e *Endpoint) []map[string]any {
	out := s.tagRefs(e.ID, "")
	add := func(refs []map[string]any) {
		for _, r := range refs {
			if !slices.ContainsFunc(out, func(x map[string]any) bool { return x["id"] == r["id"] }) {
				out = append(out, r)
			}
		}
	}
	if e.Site != nil {
		add(s.tagRefs(*e.Site, "Site"))
	}
	add(s.tagRefs(e.Org, "Organization"))
	return out
}

func (s *Server) policyDTO(scope string, id uuid.UUID) map[string]any {
	out := map[string]any{"id": nil, "scope": scope, "organizationId": nil, "siteId": nil, "endpointId": nil, "tagId": nil, "updatedAt": nil}
	for _, k := range policyKeys {
		out[k] = nil
	}
	out["excludedKbs"] = []any{}
	stored := s.policies[policyKey(scope, id)]
	if scope == ScopeGlobal && stored == nil {
		stored = globalDefaults()
	}
	for k, v := range stored {
		out[k] = v
	}
	switch scope {
	case ScopeOrganization:
		out["organizationId"] = id
	case ScopeSite:
		out["siteId"] = id
	case ScopeEndpoint:
		out["endpointId"] = id
	case ScopeTag:
		out["tagId"] = id
	}
	return out
}

// servePolicy answers GET, PUT and DELETE of a level's policy, once the
// caller's access to the level is checked.
func (s *Server) servePolicy(w http.ResponseWriter, r *http.Request, scope string, id uuid.UUID, body map[string]any) {
	if (scope == ScopeTag || (scope == ScopeGlobal && r.Method != http.MethodGet)) && !s.superAdmin() {
		problem(w, 403, "forbidden", "Only super administrators can do that.")
		return
	}
	if r.Method != http.MethodGet && s.readOnlyCall {
		problem(w, 403, "forbidden", "You do not have permission.")
		return
	}
	if s.policies == nil {
		s.policies = map[string]map[string]any{}
	}
	key := policyKey(scope, id)
	switch r.Method {
	case http.MethodGet:
		reply(w, 200, s.policyDTO(scope, id))
	case http.MethodPut:
		if (scope == ScopeEndpoint || scope == ScopeTag) && body["maxConcurrentInstallsPerSite"] != nil {
			problem(w, 400, "validation_failed", "The per-site install limit applies to a whole site and can only be set for an organization or a site.")
			return
		}
		v := map[string]any{}
		for _, k := range policyKeys {
			if x, ok := body[k]; ok && x != nil {
				v[k] = x
			}
		}
		if v["excludedKbs"] == nil {
			v["excludedKbs"] = []any{}
		}
		if scope == ScopeGlobal {
			for k, d := range globalDefaults() {
				if _, ok := v[k]; !ok {
					v[k] = d
				}
			}
		}
		v["id"], v["updatedAt"] = uuid.NewString(), time.Now().UTC()
		if old := s.policies[key]; old != nil {
			v["id"] = old["id"]
		}
		s.policies[key] = v
		reply(w, 200, s.policyDTO(scope, id))
	case http.MethodDelete:
		if scope == ScopeGlobal {
			problem(w, 405, "", "")
			return
		}
		delete(s.policies, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		problem(w, 405, "", "")
	}
}

// serveTagAssignment answers PUT /api/v1/{organizations,sites,endpoints}/{id}/tags.
func (s *Server) serveTagAssignment(w http.ResponseWriter, id uuid.UUID, body map[string]any) {
	if s.readOnlyCall || !s.unrestricted() {
		problem(w, 403, "forbidden", "Only administrators without organization restrictions can assign tags.")
		return
	}
	raw, _ := body["tagIds"].([]any)
	ids := []uuid.UUID{}
	for _, x := range raw {
		tid, err := uuid.Parse(strings.TrimSpace(x.(string)))
		if err != nil || s.findTag(tid) == nil {
			problem(w, 404, "not_found", "Tag not found.")
			return
		}
		if !slices.Contains(ids, tid) {
			ids = append(ids, tid)
		}
	}
	if len(ids) > 20 {
		problem(w, 400, "validation_failed", "An endpoint can have at most 20 tags.")
		return
	}
	if s.tagged == nil {
		s.tagged = map[uuid.UUID][]uuid.UUID{}
	}
	s.tagged[id] = ids
	w.WriteHeader(http.StatusNoContent)
}

// tagPolicies answers GET /api/v1/endpoints/{id}/tag-policies: the
// endpoint's tags that have a policy, lowest priority first, and on equal
// priority the name that sorts last first.
func (s *Server) tagPolicies(e *Endpoint) []map[string]any {
	var tags []*TagInfo
	for _, ref := range s.endpointTags(e) {
		if t := s.findTag(ref["id"].(uuid.UUID)); t != nil && s.policies[policyKey(ScopeTag, t.ID)] != nil {
			tags = append(tags, t)
		}
	}
	slices.SortFunc(tags, func(a, b *TagInfo) int {
		if a.Priority != b.Priority {
			return a.Priority - b.Priority
		}
		return strings.Compare(strings.ToLower(b.Name), strings.ToLower(a.Name))
	})
	out := []map[string]any{}
	for _, t := range tags {
		out = append(out, map[string]any{"tag": map[string]any{"id": t.ID, "name": t.Name, "color": t.Color, "inheritedFrom": nil},
			"priority": t.Priority, "policy": s.policyDTO(ScopeTag, t.ID)})
	}
	return out
}

var tagColors = []string{"gray", "blue", "green", "amber", "red", "purple", "teal", "pink"}

// serveTags answers /api/v1/tags and below.
func (s *Server) serveTags(w http.ResponseWriter, r *http.Request, parts []string, body map[string]any) {
	if len(parts) == 1 && r.Method == http.MethodGet {
		out := []map[string]any{}
		sorted := slices.Clone(s.tags)
		slices.SortFunc(sorted, func(a, b *TagInfo) int { return strings.Compare(a.Name, b.Name) })
		for _, t := range sorted {
			endpoints, sites, orgs, visible := 0, 0, 0, s.unrestricted()
			for _, e := range s.endpoints {
				if slices.ContainsFunc(s.endpointTags(e), func(x map[string]any) bool { return x["id"] == t.ID }) {
					endpoints++
					visible = visible || s.canAccess(e.Org)
				}
			}
			for _, x := range s.sites {
				if slices.Contains(s.tagged[x.ID], t.ID) {
					sites++
				}
			}
			for _, o := range s.orgs {
				if slices.Contains(s.tagged[o.ID], t.ID) {
					orgs++
					visible = visible || s.canAccess(o.ID)
				}
			}
			if !visible {
				continue
			}
			if !s.unrestricted() {
				endpoints, sites, orgs = 0, 0, 0
			}
			out = append(out, map[string]any{"id": t.ID, "name": t.Name, "color": t.Color, "description": t.Description,
				"priority": t.Priority, "endpointCount": endpoints, "hasPolicy": s.policies[policyKey(ScopeTag, t.ID)] != nil,
				"createdAt": "2026-11-02T10:00:00+00:00", "siteCount": sites, "organizationCount": orgs})
		}
		reply(w, 200, out)
		return
	}
	if !s.superAdmin() || s.readOnlyCall {
		problem(w, 403, "forbidden", "Only super administrators can do that.")
		return
	}
	var t *TagInfo
	if len(parts) >= 2 {
		id, _ := uuid.Parse(parts[1])
		if t = s.findTag(id); t == nil {
			problem(w, 404, "not_found", "Tag not found.")
			return
		}
	}
	switch {
	case len(parts) == 3 && parts[2] == "policy":
		s.servePolicy(w, r, ScopeTag, t.ID, body)
	case len(parts) == 1 && r.Method == http.MethodPost, len(parts) == 2 && r.Method == http.MethodPut:
		name, _ := body["name"].(string)
		color, _ := body["color"].(string)
		priority, _ := body["priority"].(float64)
		name = strings.TrimSpace(name)
		switch {
		case name == "" || len([]rune(name)) > 40:
			problem(w, 400, "validation_failed", "Tag name must be 1-40 characters.")
			return
		case !slices.Contains(tagColors, color):
			problem(w, 400, "validation_failed", "Color must be one of: "+strings.Join(tagColors, ", ")+".")
			return
		case priority < 0 || priority > 1000:
			problem(w, 400, "validation_failed", "Priority must be between 0 and 1000.")
			return
		case slices.ContainsFunc(s.tags, func(x *TagInfo) bool { return strings.EqualFold(x.Name, name) && x != t }):
			problem(w, 409, "tag_exists", "A tag named '"+name+"' already exists.")
			return
		}
		if t == nil {
			t = &TagInfo{ID: uuid.New()}
			s.tags = append(s.tags, t)
		}
		t.Name, t.Color, t.Priority = name, color, int(priority)
		t.Description = nil
		if d, ok := body["description"].(string); ok && strings.TrimSpace(d) != "" {
			d = strings.TrimSpace(d)
			t.Description = &d
		}
		reply(w, 200, map[string]any{"id": t.ID, "name": t.Name, "color": t.Color, "description": t.Description, "priority": t.Priority,
			"endpointCount": 0, "hasPolicy": s.policies[policyKey(ScopeTag, t.ID)] != nil, "createdAt": "2026-11-02T10:00:00+00:00",
			"siteCount": 0, "organizationCount": 0})
	case len(parts) == 2 && r.Method == http.MethodDelete:
		s.tags = slices.DeleteFunc(s.tags, func(x *TagInfo) bool { return x == t })
		delete(s.policies, policyKey(ScopeTag, t.ID))
		for id, list := range s.tagged {
			s.tagged[id] = slices.DeleteFunc(list, func(x uuid.UUID) bool { return x == t.ID })
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		problem(w, 404, "not_found", "No such route: "+r.URL.Path)
	}
}

// serveLevel answers an organization's or site's policy and tags.
func (s *Server) serveLevel(w http.ResponseWriter, r *http.Request, parts []string, body map[string]any) {
	id, _ := uuid.Parse(parts[1])
	scope, org := ScopeOrganization, id
	if parts[0] == "sites" {
		x := s.site(id)
		if x == nil {
			problem(w, 404, "not_found", "Site not found.")
			return
		}
		scope, org = ScopeSite, x.Org
	} else if s.org(id) == nil {
		problem(w, 404, "not_found", "Organization not found.")
		return
	}
	if !s.canAccess(org) {
		problem(w, 404, "not_found", "Not found.")
		return
	}
	switch {
	case parts[2] == "policy":
		s.servePolicy(w, r, scope, id, body)
	case r.Method == http.MethodPut:
		s.serveTagAssignment(w, id, body)
	default:
		problem(w, 405, "", "")
	}
}
