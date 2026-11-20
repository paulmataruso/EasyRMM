package eptest

import (
	"encoding/json"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// EasyPatch's server-wide settings (one-product plan, C6): server settings,
// vulnerability feeds, OS lifecycle entries and the audit log. The contract
// test holds these to the real server's rules.

// LifecycleInfo is an OS lifecycle entry.
type LifecycleInfo struct {
	ID                                  uuid.UUID
	Product, EditionGroup, VersionLabel string
	BuildNumber                         int
	EndOfServicing                      string
	EsuEndDate, Notes                   *string
}

func (l *LifecycleInfo) json() map[string]any {
	return map[string]any{"id": l.ID, "product": l.Product, "editionGroup": l.EditionGroup, "buildNumber": l.BuildNumber,
		"versionLabel": l.VersionLabel, "endOfServicing": l.EndOfServicing, "esuEndDate": l.EsuEndDate, "notes": l.Notes}
}

// AuditInfo is an entry of the audit log. Username is empty for EasyPatch's
// own tasks; Org is empty for server-wide entries.
type AuditInfo struct {
	ID                           int64
	Username                     string
	Org, Endpoint                *uuid.UUID
	Action, TargetType, TargetID string
	Details, IPAddress           string
	CreatedAt                    time.Time
}

func (a *AuditInfo) json() map[string]any {
	return map[string]any{"id": a.ID, "userId": nil, "username": nullable(a.Username), "organizationId": a.Org, "endpointId": a.Endpoint,
		"action": a.Action, "targetType": nullable(a.TargetType), "targetId": nullable(a.TargetID), "details": nullable(a.Details),
		"ipAddress": nullable(a.IPAddress), "correlationId": "0HTEST", "createdAt": a.CreatedAt}
}

// defaultSettings are the engine's server settings when none were saved.
func defaultSettings() map[string]any {
	return map[string]any{
		"globalMaxConcurrentInstalls": 50.0, "jobDefaultExpiryHours": 168.0, "runningJobTimeoutHours": 12.0, "waitingForRebootExpiryDays": 30.0,
		"deliveryLeaseMinutes": 10.0, "maxDeliveryAttempts": 5.0, "offlineThresholdMinutes": 10.0, "credentialLifetimeDays": 365.0,
		"credentialRotateBeforeDays": 30.0, "enrollmentRequestExpiryDays": 7.0, "retentionEventsDays": 90.0, "retentionAuditDays": 365.0,
		"retentionJobsDays": 180.0, "retentionScansDays": 90.0, "retentionHistoryDays": 730.0, "vulnerabilityFeedsEnabled": true,
		"retentionReportsMonths": 24.0, "reportBrandName": nil, "rolloutGuardEnabled": true, "rolloutGuardMinFailedEndpoints": 3.0,
		"rolloutGuardFailurePercent": 20.0, "rolloutGuardWindowDays": 7.0,
	}
}

func (s *Server) seedLifecycle() {
	if s.lifecycle != nil {
		return
	}
	s.lifecycle = []*LifecycleInfo{
		{ID: uuid.New(), Product: "Windows 11", EditionGroup: "HomePro", BuildNumber: 26100, VersionLabel: "24H2", EndOfServicing: "2026-10-13"},
		{ID: uuid.New(), Product: "Windows Server", EditionGroup: "Server", BuildNumber: 26100, VersionLabel: "2025", EndOfServicing: "2034-10-10"},
	}
}

// ServerSettings is the server settings as saved, every field.
func (s *Server) ServerSettings() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.settings == nil {
		return defaultSettings()
	}
	return maps.Clone(s.settings)
}

// SetFeeds sets the vulnerability feeds' state, as vulnerability-feeds
// lists it.
func (s *Server) SetFeeds(feeds []map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.feeds = feeds
}

// LifecycleEntries lists the OS lifecycle entries.
func (s *Server) LifecycleEntries() []LifecycleInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seedLifecycle()
	out := make([]LifecycleInfo, 0, len(s.lifecycle))
	for _, l := range s.lifecycle {
		out = append(out, *l)
	}
	return out
}

// AddAudit adds an entry to the audit log and returns its id; a zero
// CreatedAt is now.
func (s *Server) AddAudit(a AuditInfo) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addAudit(a)
}

func (s *Server) addAudit(a AuditInfo) int64 {
	s.auditSeq++
	a.ID = s.auditSeq
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	s.audit = append(s.audit, &a)
	return a.ID
}

func (s *Server) serveSettings(w http.ResponseWriter, r *http.Request, body map[string]any) {
	if s.settings == nil {
		s.settings = defaultSettings()
	}
	switch r.Method {
	case http.MethodGet:
		reply(w, 200, s.settings)
	case http.MethodPut:
		if !s.superAdmin() {
			problem(w, 403, "forbidden", "You do not have permission.")
			return
		}
		// EasyPatch replaces every setting: one left out takes its default.
		next := defaultSettings()
		for k := range next {
			if v, ok := body[k]; ok {
				next[k] = v
			}
		}
		if n, _ := next["globalMaxConcurrentInstalls"].(float64); n < 1 || n > 10_000 {
			problem(w, 400, "validation_failed", "GlobalMaxConcurrentInstalls must be between 1 and 10000.")
			return
		}
		s.settings = next
		b, _ := json.Marshal(body)
		s.addAudit(AuditInfo{Username: s.actorName(), Action: "settings.update", TargetType: "ServerSettings", TargetID: "1", Details: string(b)})
		reply(w, 200, s.settings)
	default:
		problem(w, 405, "", "")
	}
}

func (s *Server) serveFeeds(w http.ResponseWriter) {
	feeds := s.feeds
	if feeds == nil {
		feeds = []map[string]any{}
	}
	reply(w, 200, feeds)
}

func lifecycleFrom(body map[string]any) (*LifecycleInfo, string) {
	str := func(k string) string { v, _ := body[k].(string); return strings.TrimSpace(v) }
	ptr := func(k string) *string {
		if v, ok := body[k].(string); ok {
			return &v
		}
		return nil
	}
	build, _ := body["buildNumber"].(float64)
	l := &LifecycleInfo{Product: str("product"), EditionGroup: str("editionGroup"), VersionLabel: str("versionLabel"), BuildNumber: int(build),
		EndOfServicing: str("endOfServicing"), EsuEndDate: ptr("esuEndDate"), Notes: ptr("notes")}
	switch {
	case l.Product == "" || l.EditionGroup == "" || l.VersionLabel == "":
		return nil, "product"
	case l.BuildNumber < 1 || l.BuildNumber > 1_000_000:
		return nil, "buildNumber"
	}
	if _, err := time.Parse(time.DateOnly, l.EndOfServicing); err != nil {
		return nil, "endOfServicing"
	}
	if l.EsuEndDate != nil && *l.EsuEndDate < l.EndOfServicing {
		return nil, "esuEndDate"
	}
	return l, ""
}

func (s *Server) serveLifecycle(w http.ResponseWriter, r *http.Request, parts []string, body map[string]any) {
	s.seedLifecycle()
	if r.Method == http.MethodGet && len(parts) == 1 {
		out := make([]map[string]any, 0, len(s.lifecycle))
		for _, l := range s.lifecycle {
			out = append(out, l.json())
		}
		reply(w, 200, out)
		return
	}
	if !s.superAdmin() {
		problem(w, 403, "forbidden", "You do not have permission.")
		return
	}
	var cur *LifecycleInfo
	if len(parts) == 2 {
		id, _ := uuid.Parse(parts[1])
		i := slices.IndexFunc(s.lifecycle, func(l *LifecycleInfo) bool { return l.ID == id })
		if i < 0 {
			problem(w, 404, "not_found", "Lifecycle entry was not found.")
			return
		}
		cur = s.lifecycle[i]
	}
	switch {
	case r.Method == http.MethodDelete && cur != nil:
		s.lifecycle = slices.DeleteFunc(s.lifecycle, func(l *LifecycleInfo) bool { return l == cur })
		s.addAudit(AuditInfo{Username: s.actorName(), Action: "lifecycle.delete", TargetType: "OsLifecycleEntry", TargetID: cur.ID.String()})
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && cur == nil, r.Method == http.MethodPut && cur != nil:
		l, field := lifecycleFrom(body)
		if l == nil {
			problem(w, 400, "validation_failed", field+" is not valid.")
			return
		}
		for _, o := range s.lifecycle {
			if o != cur && o.Product == l.Product && o.EditionGroup == l.EditionGroup && o.BuildNumber == l.BuildNumber {
				problem(w, 409, "conflict", "A record with the same unique value already exists.")
				return
			}
		}
		action := "lifecycle.update"
		if cur == nil {
			l.ID, action = uuid.New(), "lifecycle.create"
			s.lifecycle = append(s.lifecycle, l)
		} else {
			l.ID = cur.ID
			*cur = *l
		}
		s.addAudit(AuditInfo{Username: s.actorName(), Action: action, TargetType: "OsLifecycleEntry", TargetID: l.ID.String()})
		status := 200
		if action == "lifecycle.create" {
			status = 201
		}
		reply(w, status, l.json())
	default:
		problem(w, 405, "", "")
	}
}

// serveAudit lists the audit log, newest first, as an Operator sees it:
// the entries of the organizations the request may see, and every entry
// for one that may see every organization.
func (s *Server) serveAudit(w http.ResponseWriter, q url.Values, page, size int) {
	if s.readOnlyCall {
		problem(w, 403, "forbidden", "You do not have permission.")
		return
	}
	org, _ := uuid.Parse(q.Get("organizationId"))
	action := q.Get("action")
	from, _ := time.Parse(time.RFC3339, q.Get("from"))
	to, _ := time.Parse(time.RFC3339, q.Get("to"))
	var out []map[string]any
	for _, a := range slices.Backward(s.audit) {
		switch {
		case a.Org == nil && !s.unrestricted(), a.Org != nil && !s.canAccess(*a.Org):
		case org != uuid.Nil && (a.Org == nil || *a.Org != org):
		case action != "" && !strings.HasPrefix(a.Action, action):
		case !from.IsZero() && a.CreatedAt.Before(from), !to.IsZero() && !a.CreatedAt.Before(to):
		default:
			out = append(out, a.json())
		}
	}
	reply(w, 200, paged(out, page, size))
}
