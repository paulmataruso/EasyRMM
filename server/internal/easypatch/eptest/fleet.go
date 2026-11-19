package eptest

import (
	"cmp"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// The update catalog across endpoints, one update's endpoints, installing
// or removing it on many endpoints, and holds, as EasyPatch's
// /api/v1/updates and /api/v1/update-holds answer them (one-product plan,
// C2). An update is the same on every endpoint that reports it: its GUID
// comes from its title.

// HoldInfo is an update hold.
type HoldInfo struct {
	ID, Update uuid.UUID
	// Org is nil for a hold in every organization.
	Org            *uuid.UUID
	Source, Reason string
	CreatedBy      string
	CreatedAt      time.Time
	Released       bool
	ReleasedBy     string
}

// UpdateGUID is the GUID of the update with a title on every endpoint.
func UpdateGUID(title string) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("easypatch-test:"+title))
}

// AddHold holds an update, as EasyPatch's rollout guard (source Automatic)
// or a person (Manual) does; org nil holds it everywhere.
func (s *Server) AddHold(update uuid.UUID, org *uuid.UUID, source, reason string) uuid.UUID {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := &HoldInfo{ID: uuid.New(), Update: update, Org: org, Source: source, Reason: reason, CreatedBy: "rollout guard",
		CreatedAt: time.Now().UTC()}
	s.holds = append(s.holds, h)
	return h.ID
}

// Holds lists every hold, released ones too, oldest first.
func (s *Server) Holds() []HoldInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]HoldInfo, 0, len(s.holds))
	for _, h := range s.holds {
		out = append(out, *h)
	}
	return out
}

// role is the request's role, as its statement names it.
func (s *Server) role() string {
	return s.requests[len(s.requests)-1].Statement.Role
}

// canAccess is whether the request may see an organization.
func (s *Server) canAccess(org uuid.UUID) bool {
	if s.unrestricted() {
		return true
	}
	return slices.Contains(s.requests[len(s.requests)-1].Statement.Organizations, org)
}

type fleetRow struct {
	e *Endpoint
	u map[string]any
}

// fleetScope lists the updates of the active endpoints the request may see,
// in an organization and a site when it names them, by host name.
func (s *Server) fleetScope(org, site string) []fleetRow {
	o, _ := uuid.Parse(org)
	x, _ := uuid.Parse(site)
	var rows []fleetRow
	for _, e := range s.sorted() {
		if e.Status != "Active" || !s.canAccess(e.Org) || (o != uuid.Nil && e.Org != o) || (x != uuid.Nil && (e.Site == nil || *e.Site != x)) {
			continue
		}
		for _, u := range append(slices.Clone(e.Updates), e.InstalledItems...) {
			rows = append(rows, fleetRow{e, u})
		}
	}
	return rows
}

type fleetCounts struct {
	guid                                                                uuid.UUID
	u                                                                   map[string]any
	missing, failed, installed, pending, excluded, exploited, reoffered int
}

func count(rows []fleetRow) []*fleetCounts {
	var out []*fleetCounts
	by := map[uuid.UUID]*fleetCounts{}
	for _, r := range rows {
		guid := r.u["updateGuid"].(uuid.UUID)
		c := by[guid]
		if c == nil {
			c = &fleetCounts{guid: guid, u: r.u}
			by[guid] = c
			out = append(out, c)
		}
		switch r.u["state"] {
		case "Missing":
			c.missing++
		case "Failed":
			c.failed++
		case "Installed":
			c.installed++
		case "PendingReboot", "PendingVerification":
			c.pending++
		case "Reoffered":
			c.reoffered++
		}
		if r.u["state"] == "Excluded" || r.u["isExcluded"] == true {
			c.excluded++
		}
		if r.u["knownExploited"] == true {
			c.exploited++
		}
	}
	return out
}

// held is whether an update has an active hold the request sees, for
// every organization or for org when it names one.
func (s *Server) held(guid uuid.UUID, org string) bool {
	o, _ := uuid.Parse(org)
	for _, h := range s.visibleHolds() {
		if h.Update == guid && (o == uuid.Nil || h.Org == nil || *h.Org == o) {
			return true
		}
	}
	return false
}

func (c *fleetCounts) dto(onHold bool) map[string]any {
	cves, _ := c.u["cveIds"].([]string)
	return map[string]any{"updateGuid": c.guid, "title": c.u["title"], "kbNumber": c.u["kbNumber"], "category": c.u["category"],
		"msrcSeverity": c.u["msrcSeverity"], "releaseDate": c.u["releaseDate"], "sizeBytes": c.u["sizeBytes"], "missingCount": c.missing,
		"failedCount": c.failed, "installedCount": c.installed, "pendingRebootCount": c.pending, "excludedCount": c.excluded,
		"package": c.u["package"], "cveCount": len(cves), "knownExploited": c.exploited > 0, "reofferedCount": c.reoffered, "onHold": onHold}
}

// serveFleet answers /api/v1/updates/...; parts follow "updates".
func (s *Server) serveFleet(w http.ResponseWriter, r *http.Request, parts []string, body map[string]any, q url.Values, pg, size int) {
	if len(parts) == 0 && r.Method == http.MethodGet {
		s.catalog(w, q, pg, size)
		return
	}
	if len(parts) == 0 {
		problem(w, 405, "", "")
		return
	}
	guid, err := uuid.Parse(parts[0])
	if err != nil {
		problem(w, 404, "not_found", "No such route.")
		return
	}
	sub := strings.Join(parts[1:], "/")
	if r.Method == http.MethodPost && s.readOnlyCall {
		problem(w, 403, "forbidden", "You do not have permission.")
		return
	}
	switch {
	case r.Method == http.MethodGet && sub == "":
		s.fleetUpdate(w, guid, q)
	case r.Method == http.MethodGet && sub == "endpoints":
		list := []map[string]any{}
		for _, row := range s.fleetScope(q.Get("organizationId"), q.Get("siteId")) {
			if row.u["updateGuid"] != guid || (q.Get("state") != "" && row.u["state"] != q.Get("state")) {
				continue
			}
			list = append(list, map[string]any{"endpointId": row.e.ID, "hostname": row.e.Hostname, "organizationName": row.e.OrgName,
				"siteName": nullable(row.e.SiteName), "isOnline": true, "state": row.u["state"], "isRequired": row.u["isRequired"],
				"isExcluded": row.u["isExcluded"], "failedAttempts": row.u["failedAttempts"], "errorCode": row.u["errorCode"],
				"errorMessage": row.u["errorMessage"], "stateChangedAt": row.u["stateChangedAt"]})
		}
		reply(w, 200, paged(list, pg, size))
	case r.Method == http.MethodPost && (sub == "install" || sub == "uninstall"):
		s.fleetAction(w, guid, sub, body)
	case r.Method == http.MethodPost && sub == "holds":
		s.hold(w, guid, body)
	default:
		problem(w, 404, "not_found", "No such route.")
	}
}

func (s *Server) catalog(w http.ResponseWriter, q url.Values, pg, size int) {
	var rows []fleetRow
	search := strings.ToLower(strings.TrimSpace(q.Get("search")))
	for _, row := range s.fleetScope(q.Get("organizationId"), q.Get("siteId")) {
		kb, _ := row.u["kbNumber"].(string)
		title, _ := row.u["title"].(string)
		if (q.Get("category") == "" || row.u["category"] == q.Get("category")) &&
			(search == "" || strings.Contains(strings.ToLower(title), search) || strings.Contains(strings.ToLower(kb), search)) {
			rows = append(rows, row)
		}
	}
	var list []*fleetCounts
	for _, c := range count(rows) {
		if v := q.Get("knownExploited"); v != "" && (c.exploited > 0) != (v == "true") {
			continue
		}
		keep := c.missing > 0 || c.failed > 0 || c.pending > 0 || c.reoffered > 0
		switch q.Get("state") {
		case "Missing":
			keep = c.missing > 0
		case "Failed":
			keep = c.failed > 0
		case "Installed":
			keep = c.installed > 0
		case "PendingReboot", "PendingVerification":
			keep = c.pending > 0
		case "Excluded":
			keep = c.excluded > 0
		case "Reoffered":
			keep = c.reoffered > 0
		}
		if keep {
			list = append(list, c)
		}
	}
	key := func(c *fleetCounts) int {
		switch strings.ToLower(q.Get("sort")) {
		case "failed":
			return c.failed
		case "installed":
			return c.installed
		case "missing":
			return c.missing + c.failed
		}
		exploited := 0
		if c.exploited > 0 {
			exploited = 1_000_000
		}
		return exploited + c.missing + c.failed
	}
	slices.SortStableFunc(list, func(a, b *fleetCounts) int {
		if q.Get("dir") == "asc" {
			return cmp.Compare(key(a), key(b))
		}
		return cmp.Compare(key(b), key(a))
	})
	items := make([]map[string]any, 0, len(list))
	for _, c := range list {
		items = append(items, c.dto(s.held(c.guid, q.Get("organizationId"))))
	}
	reply(w, 200, paged(items, pg, size))
}

func (s *Server) fleetUpdate(w http.ResponseWriter, guid uuid.UUID, q url.Values) {
	// The catalog covers every organization, as EasyPatch's does.
	var known map[string]any
	for _, e := range s.endpoints {
		for _, u := range append(slices.Clone(e.Updates), e.InstalledItems...) {
			if u["updateGuid"] == guid {
				known = u
			}
		}
	}
	if known == nil {
		problem(w, 404, "not_found", "Update not found.")
		return
	}
	var rows []fleetRow
	cves := map[string]bool{}
	for _, row := range s.fleetScope(q.Get("organizationId"), q.Get("siteId")) {
		if row.u["updateGuid"] == guid {
			rows = append(rows, row)
			for _, c := range row.u["cveIds"].([]string) {
				cves[c] = true
			}
		}
	}
	c := &fleetCounts{guid: guid, u: known}
	if counted := count(rows); len(counted) == 1 {
		c = counted[0]
	}
	vulns := []map[string]any{}
	for _, id := range slices.Sorted(func(yield func(string) bool) {
		for k := range cves {
			if !yield(k) {
				return
			}
		}
	}) {
		vulns = append(vulns, map[string]any{"cveId": id, "title": nil, "severity": "Important", "cvssBase": 7.5, "msrcExploited": false,
			"kev": c.exploited > 0, "kevDateAdded": nil, "kevDueDate": nil, "kevRansomware": false, "kevName": nil})
	}
	holds := []map[string]any{}
	org, _ := uuid.Parse(q.Get("organizationId"))
	onHold := false
	for _, h := range s.visibleHolds() {
		if h.Update == guid {
			holds = append(holds, s.holdDTO(h))
			onHold = onHold || h.Org == nil || org == uuid.Nil || *h.Org == org
		}
	}
	dto := c.dto(onHold)
	dto["cveCount"] = len(cves)
	reply(w, 200, map[string]any{"summary": dto, "description": known["description"], "supportUrl": known["supportUrl"],
		"kbNumbers": known["kbNumbers"], "products": []string{"Debian 13"}, "msClassification": known["msClassification"],
		"rebootLikely": known["rebootLikely"], "supersededUpdateGuids": []string{}, "vulnerabilities": vulns, "holds": holds})
}

// fleetAction installs an update on, or removes it from, the endpoints in
// scope where it is missing or failed and not excluded (an install), or
// installed or waiting for its restart (a removal): those of endpointIds
// when it names some, every one otherwise.
func (s *Server) fleetAction(w http.ResponseWriter, guid uuid.UUID, kind string, body map[string]any) {
	reason, _ := body["reason"].(string)
	if len([]rune(reason)) > 500 {
		problem(w, 400, "validation_failed", "One or more fields are invalid.")
		return
	}
	chosen := map[uuid.UUID]bool{}
	ids, _ := body["endpointIds"].([]any)
	for _, raw := range ids {
		id, _ := uuid.Parse(fmt.Sprint(raw))
		chosen[id] = true
	}
	org, _ := body["organizationId"].(string)
	site, _ := body["siteId"].(string)
	results := []map[string]any{}
	succeeded, failed := 0, 0
	seen := map[uuid.UUID]bool{}
	for _, row := range s.fleetScope(org, site) {
		st := row.u["state"]
		eligible := (st == "Missing" || st == "Failed") && row.u["isExcluded"] != true
		if kind == "uninstall" {
			eligible = st == "Installed" || st == "PendingReboot"
		}
		if row.u["updateGuid"] != guid || !eligible || (len(chosen) > 0 && !chosen[row.e.ID]) || seen[row.e.ID] {
			continue
		}
		seen[row.e.ID] = true
		if kind == "uninstall" && !row.e.Windows {
			results = append(results, map[string]any{"endpointId": row.e.ID, "hostname": row.e.Hostname, "success": false, "jobId": nil,
				"errorCode": "not_supported_on_linux", "message": row.e.Hostname + " is a Linux endpoint. Removing updates is only available on Windows."})
			failed++
			continue
		}
		typ := "InstallUpdates"
		if kind == "uninstall" {
			typ = "UninstallUpdate"
			if body["block"] == true {
				row.e.exclude(guid, true)
				row.u["isExcluded"] = true
			}
		}
		j := s.newJob(row.e, typ, nil)
		results = append(results, map[string]any{"endpointId": row.e.ID, "hostname": row.e.Hostname, "success": true, "jobId": j.ID,
			"errorCode": nil, "message": nil})
		succeeded++
	}
	reply(w, 200, map[string]any{"succeeded": succeeded, "failed": failed, "results": results})
}

// visibleHolds are the active holds for every organization and for those
// the request may see.
func (s *Server) visibleHolds() []*HoldInfo {
	var out []*HoldInfo
	for _, h := range s.holds {
		if !h.Released && (h.Org == nil || s.canAccess(*h.Org)) {
			out = append(out, h)
		}
	}
	slices.SortStableFunc(out, func(a, b *HoldInfo) int {
		if (a.Org == nil) != (b.Org == nil) {
			if a.Org == nil {
				return -1
			}
			return 1
		}
		return a.CreatedAt.Compare(b.CreatedAt)
	})
	return out
}

func (s *Server) holdDTO(h *HoldInfo) map[string]any {
	title, kb := any(nil), any(nil)
	for _, e := range s.endpoints {
		for _, u := range append(slices.Clone(e.Updates), e.InstalledItems...) {
			if u["updateGuid"] == h.Update {
				title, kb = u["title"], u["kbNumber"]
			}
		}
	}
	role := s.role()
	operator := role == "Admin" || role == "SuperAdmin"
	canRelease := !h.Released && operator && ((h.Org != nil && s.canAccess(*h.Org)) || (h.Org == nil && role == "SuperAdmin"))
	var orgName, released, releasedBy any
	if h.Org != nil {
		if o := s.org(*h.Org); o != nil {
			orgName = o.Name
		}
	}
	if h.Released {
		released, releasedBy = "2026-11-18T10:00:00+00:00", h.ReleasedBy
	}
	return map[string]any{"id": h.ID, "updateGuid": h.Update, "title": title, "kbNumber": kb, "organizationId": h.Org,
		"organizationName": orgName, "source": h.Source, "reason": h.Reason, "failedEndpoints": nil, "attemptedEndpoints": nil,
		"createdAt": h.CreatedAt, "createdBy": h.CreatedBy, "releasedAt": released, "releasedBy": releasedBy, "canRelease": canRelease}
}

// actorName is who EasyPatch records a change as.
func (s *Server) actorName() string {
	return "easyrmm:" + s.requests[len(s.requests)-1].Statement.Name
}

// hold answers POST /api/v1/updates/{guid}/holds.
func (s *Server) hold(w http.ResponseWriter, guid uuid.UUID, body map[string]any) {
	reason, _ := body["reason"].(string)
	reason = strings.TrimSpace(reason)
	if reason == "" || len([]rune(reason)) > 500 {
		problem(w, 400, "validation_failed", "One or more fields are invalid.")
		return
	}
	var org *uuid.UUID
	if v, ok := body["organizationId"].(string); ok {
		id, err := uuid.Parse(v)
		if err != nil || !s.canAccess(id) {
			problem(w, 403, "forbidden", "You do not have access to this organization.")
			return
		}
		if o := s.org(id); o == nil || !o.Active {
			problem(w, 404, "not_found", "Organization not found.")
			return
		}
		org = &id
	} else if s.role() != "SuperAdmin" {
		problem(w, 403, "forbidden", "Only super administrators can hold an update for every organization. Choose an organization.")
		return
	}
	known := false
	for _, e := range s.endpoints {
		for _, u := range append(slices.Clone(e.Updates), e.InstalledItems...) {
			known = known || u["updateGuid"] == guid
		}
	}
	if !known {
		problem(w, 404, "not_found", "Update not found.")
		return
	}
	for _, h := range s.holds {
		if h.Update == guid && !h.Released && ((h.Org == nil && org == nil) || (h.Org != nil && org != nil && *h.Org == *org)) {
			problem(w, 409, "already_held", "This update is already on hold.")
			return
		}
	}
	h := &HoldInfo{ID: uuid.New(), Update: guid, Org: org, Source: "Manual", Reason: reason, CreatedBy: s.actorName(), CreatedAt: time.Now().UTC()}
	s.holds = append(s.holds, h)
	reply(w, 201, s.holdDTO(h))
}

// serveHolds answers /api/v1/update-holds/...; parts follow "update-holds".
func (s *Server) serveHolds(w http.ResponseWriter, r *http.Request, parts []string, q url.Values) {
	switch {
	case len(parts) == 0 && r.Method == http.MethodGet:
		guid, _ := uuid.Parse(q.Get("updateGuid"))
		list := []map[string]any{}
		for _, h := range s.visibleHolds() {
			if guid == uuid.Nil || h.Update == guid {
				list = append(list, s.holdDTO(h))
			}
		}
		reply(w, 200, list)
	case len(parts) == 2 && parts[1] == "release" && r.Method == http.MethodPost:
		if s.readOnlyCall {
			problem(w, 403, "forbidden", "You do not have permission.")
			return
		}
		id, _ := uuid.Parse(parts[0])
		i := slices.IndexFunc(s.holds, func(h *HoldInfo) bool { return h.ID == id })
		if i < 0 {
			problem(w, 404, "not_found", "Hold not found.")
			return
		}
		h := s.holds[i]
		switch {
		case h.Org != nil && !s.canAccess(*h.Org):
			problem(w, 403, "forbidden", "You do not have access to this organization.")
			return
		case h.Org == nil && s.role() != "SuperAdmin":
			problem(w, 403, "forbidden", "Only super administrators can release a hold that applies to every organization.")
			return
		}
		if !h.Released {
			h.Released, h.ReleasedBy = true, s.actorName()
		}
		reply(w, 200, s.holdDTO(h))
	default:
		problem(w, 404, "not_found", "No such route.")
	}
}
