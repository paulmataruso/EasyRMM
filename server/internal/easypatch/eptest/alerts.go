package eptest

import (
	"cmp"
	"net/http"
	"net/mail"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// EasyPatch's alerts and notifications: alerts, the rules that raise them,
// notification channels and their deliveries. The contract test holds these
// to the real server's rules.

// AlertInfo is an alert. Endpoint is nil for an organization's alert;
// Status is Open, Acknowledged or Resolved.
type AlertInfo struct {
	ID                         uuid.UUID
	Rule                       *uuid.UUID
	RuleType, Severity, Status string
	Title, Details             string
	Org                        uuid.UUID
	Endpoint                   *uuid.UUID
	OpenedAt                   time.Time
	ResolvedAt, AcknowledgedAt *time.Time
	AcknowledgedBy             string
}

// RuleInfo is an alert rule.
type RuleInfo struct {
	ID                       uuid.UUID
	Name, Type, Severity     string
	Enabled, NotifyOnResolve bool
	Threshold                *int
	Org, Tag                 *uuid.UUID
	Channels                 []uuid.UUID
	RenotifyHours            int
	UpdatedAt                time.Time
}

// ChannelInfo is a notification channel.
type ChannelInfo struct {
	ID                   uuid.UUID
	Name, Type           string
	Enabled              bool
	Emails               []string
	Format               *string
	URL, Host, Secret    string
	CreatedAt, UpdatedAt time.Time
}

// DeliveryInfo is a message to a channel.
type DeliveryInfo struct {
	ID                    uuid.UUID
	Channel               uuid.UUID
	Kind, Subject, Status string
	LastError             string
	CreatedAt             time.Time
}

type ruleSpec struct {
	unit              string
	min, max, initial int
}

var ruleSpecs = map[string]ruleSpec{
	"EndpointOffline":       {"hours", 1, 720, 24},
	"SecurityUpdateMissing": {"days", 0, 365, 14},
	"RestartPending":        {"days", 1, 90, 7},
	"OsUnsupported":         {"days", 0, 365, 30},
}

var ruleTypes = []string{"EndpointOffline", "InstallFailed", "SecurityUpdateMissing", "ScanStale", "RestartPending",
	"OsUnsupported", "KnownExploitedMissing", "UpdateHeld"}

func endpointRule(t string) bool { return t != "UpdateHeld" }

// seedRules adds EasyPatch's rules on install, once.
func (s *Server) seedRules() {
	if s.rulesSeeded {
		return
	}
	s.rulesSeeded = true
	// The IDs are EasyPatch's; 6 was the retired EnrollmentPending rule's.
	for _, d := range [][4]string{
		{"1", "Endpoint offline", "EndpointOffline", "Warning"},
		{"2", "Update installation failed", "InstallFailed", "Warning"},
		{"3", "Security update missing", "SecurityUpdateMissing", "Critical"},
		{"4", "Scan stale", "ScanStale", "Warning"},
		{"5", "Restart pending", "RestartPending", "Info"},
		{"7", "Operating system unsupported", "OsUnsupported", "Warning"},
		{"8", "Known-exploited vulnerability unpatched", "KnownExploitedMissing", "Critical"},
		{"9", "Update on hold", "UpdateHeld", "Warning"},
	} {
		r := &RuleInfo{ID: uuid.MustParse("7c3e1a52-6f0e-4d7b-9a01-00000000000" + d[0]), Name: d[1], Type: d[2], Severity: d[3],
			Enabled: true, UpdatedAt: time.Now().UTC()}
		if spec, ok := ruleSpecs[d[2]]; ok {
			n := spec.initial
			r.Threshold = &n
		}
		s.rules = append(s.rules, r)
	}
}

// AddAlert adds an alert, Open unless Status says otherwise, and returns
// its id.
func (s *Server) AddAlert(a AlertInfo) uuid.UUID {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	if a.Status == "" {
		a.Status = "Open"
	}
	if a.OpenedAt.IsZero() {
		a.OpenedAt = time.Now().UTC()
	}
	s.alerts = append(s.alerts, &a)
	return a.ID
}

// AlertState is an alert as it is now.
func (s *Server) AlertState(id uuid.UUID) (AlertInfo, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := slices.IndexFunc(s.alerts, func(a *AlertInfo) bool { return a.ID == id })
	if i < 0 {
		return AlertInfo{}, false
	}
	return *s.alerts[i], true
}

// Deliveries lists the deliveries, oldest first.
func (s *Server) Deliveries() []DeliveryInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]DeliveryInfo, 0, len(s.deliveries))
	for _, d := range s.deliveries {
		out = append(out, *d)
	}
	return out
}

func (s *Server) alertJSON(a *AlertInfo) map[string]any {
	var ruleName any
	if a.Rule != nil {
		if i := slices.IndexFunc(s.rules, func(r *RuleInfo) bool { return r.ID == *a.Rule }); i >= 0 {
			ruleName = s.rules[i].Name
		}
	}
	orgName := ""
	if o := s.org(a.Org); o != nil {
		orgName = o.Name
	}
	var hostname any
	if a.Endpoint != nil {
		if e := s.endpoints[*a.Endpoint]; e != nil {
			hostname = e.Hostname
		}
	}
	return map[string]any{"id": a.ID, "ruleId": a.Rule, "ruleName": ruleName, "ruleType": a.RuleType, "severity": a.Severity, "status": a.Status,
		"title": a.Title, "details": nullable(a.Details), "organizationId": a.Org, "organizationName": orgName, "endpointId": a.Endpoint,
		"hostname": hostname, "openedAt": a.OpenedAt, "lastSeenAt": a.OpenedAt, "resolvedAt": a.ResolvedAt, "acknowledgedAt": a.AcknowledgedAt,
		"acknowledgedBy": nullable(a.AcknowledgedBy)}
}

var severityRank = map[string]int{"Critical": 2, "Warning": 1}

// visibleAlerts is the alerts of the statement's organizations, in
// EasyPatch's order: unresolved first, the most severe, the newest.
func (s *Server) visibleAlerts() []*AlertInfo {
	var out []*AlertInfo
	for _, a := range s.alerts {
		if s.canAccess(a.Org) {
			out = append(out, a)
		}
	}
	slices.SortStableFunc(out, func(a, b *AlertInfo) int {
		ra, rb := a.Status == "Resolved", b.Status == "Resolved"
		if ra != rb {
			if ra {
				return 1
			}
			return -1
		}
		return cmp.Or(severityRank[b.Severity]-severityRank[a.Severity], b.OpenedAt.Compare(a.OpenedAt))
	})
	return out
}

func (s *Server) serveAlerts(w http.ResponseWriter, r *http.Request, parts []string, q url.Values, body map[string]any, page, size int) {
	switch {
	case r.Method == http.MethodGet && len(parts) == 1:
		status := strings.ToLower(q.Get("status"))
		org, _ := uuid.Parse(q.Get("organizationId"))
		endpoint, _ := uuid.Parse(q.Get("endpointId"))
		search := strings.ToLower(strings.TrimSpace(q.Get("search")))
		if !slices.Contains([]string{"", "unresolved", "open", "acknowledged", "resolved", "all"}, status) {
			problem(w, 400, "validation_failed", "status must be unresolved, open, acknowledged, resolved or all.")
			return
		}
		out := []map[string]any{}
		for _, a := range s.visibleAlerts() {
			switch {
			case (status == "" || status == "unresolved") && a.Status == "Resolved",
				status == "open" && a.Status != "Open", status == "acknowledged" && a.Status != "Acknowledged",
				status == "resolved" && a.Status != "Resolved":
			case q.Get("severity") != "" && a.Severity != q.Get("severity"):
			case q.Get("ruleType") != "" && a.RuleType != q.Get("ruleType"):
			case org != uuid.Nil && a.Org != org:
			case endpoint != uuid.Nil && (a.Endpoint == nil || *a.Endpoint != endpoint):
			case search != "" && !strings.Contains(strings.ToLower(a.Title), search):
			default:
				out = append(out, s.alertJSON(a))
			}
		}
		reply(w, 200, paged(out, page, min(size, 200)))
	case r.Method == http.MethodGet && len(parts) == 2 && parts[1] == "summary":
		sum := map[string]int{"open": 0, "acknowledged": 0, "critical": 0, "warning": 0, "info": 0}
		for _, a := range s.visibleAlerts() {
			if a.Status == "Resolved" {
				continue
			}
			sum[strings.ToLower(a.Status)]++
			sum[strings.ToLower(a.Severity)]++
		}
		reply(w, 200, sum)
	case r.Method == http.MethodPost && len(parts) == 2 && parts[1] == "acknowledge":
		if s.role() != "Admin" && s.role() != "SuperAdmin" {
			problem(w, 403, "forbidden", "You do not have permission.")
			return
		}
		raw, _ := body["alertIds"].([]any)
		if len(raw) == 0 || len(raw) > 500 {
			problem(w, 400, "validation_failed", "Select 1 to 500 alerts.")
			return
		}
		n := 0
		now := time.Now().UTC()
		for _, a := range s.visibleAlerts() {
			if a.Status == "Open" && slices.Contains(raw, any(a.ID.String())) {
				a.Status, a.AcknowledgedAt, a.AcknowledgedBy = "Acknowledged", &now, s.actorName()
				n++
			}
		}
		if n > 0 {
			s.addAudit(AuditInfo{Username: s.actorName(), Action: "alert.acknowledge", TargetType: "Alert"})
		}
		reply(w, 200, map[string]int{"acknowledged": n})
	default:
		problem(w, 405, "", "")
	}
}

func (s *Server) ruleJSON(rule *RuleInfo) map[string]any {
	open := 0
	for _, a := range s.alerts {
		if a.Rule != nil && *a.Rule == rule.ID && a.Status != "Resolved" {
			open++
		}
	}
	var unit any
	if spec, ok := ruleSpecs[rule.Type]; ok {
		unit = spec.unit
	}
	channels := rule.Channels
	if channels == nil {
		channels = []uuid.UUID{}
	}
	return map[string]any{"id": rule.ID, "name": rule.Name, "type": rule.Type, "enabled": rule.Enabled, "severity": rule.Severity,
		"threshold": rule.Threshold, "thresholdUnit": unit, "organizationId": rule.Org, "tagId": rule.Tag, "channelIds": channels,
		"notifyOnResolve": rule.NotifyOnResolve, "renotifyHours": rule.RenotifyHours, "unresolvedAlerts": open, "updatedAt": rule.UpdatedAt}
}

// ruleFrom reads and checks a rule as EasyPatch does; problems are its
// sentences, joined.
func (s *Server) ruleFrom(body map[string]any) (*RuleInfo, string) {
	str := func(k string) string { v, _ := body[k].(string); return v }
	flag := func(k string) bool { v, _ := body[k].(bool); return v }
	id := func(k string) *uuid.UUID {
		if v, err := uuid.Parse(str(k)); err == nil {
			return &v
		}
		return nil
	}
	r := &RuleInfo{Name: strings.TrimSpace(str("name")), Type: str("type"), Severity: str("severity"), Enabled: flag("enabled"),
		NotifyOnResolve: flag("notifyOnResolve"), Org: id("organizationId"), Tag: id("tagId"), UpdatedAt: time.Now().UTC()}
	if n, ok := body["renotifyHours"].(float64); ok {
		r.RenotifyHours = int(n)
	}
	if raw, ok := body["channelIds"].([]any); ok {
		for _, c := range raw {
			if v, err := uuid.Parse(c.(string)); err == nil && !slices.Contains(r.Channels, v) {
				r.Channels = append(r.Channels, v)
			}
		}
	}
	var errs []string
	if r.Name == "" || len([]rune(r.Name)) > 100 {
		errs = append(errs, "Name must be 1-100 characters.")
	}
	if !slices.Contains(ruleTypes, r.Type) {
		return nil, strings.Join(append(errs, "Unknown rule type."), " ")
	}
	spec, has := ruleSpecs[r.Type]
	if n, ok := body["threshold"].(float64); ok && has {
		t := int(n)
		r.Threshold = &t
	}
	if has && (r.Threshold == nil || *r.Threshold < spec.min || *r.Threshold > spec.max) {
		errs = append(errs, "Threshold must be between the type's bounds.")
	}
	if r.RenotifyHours < 0 || r.RenotifyHours > 720 {
		errs = append(errs, "Reminder interval must be between 0 (never) and 720 hours.")
	}
	if len(r.Channels) > 20 {
		errs = append(errs, "At most 20 channels per rule.")
	}
	if r.Tag != nil && !endpointRule(r.Type) {
		errs = append(errs, "This rule type cannot be limited to a tag.")
	}
	if !slices.Contains([]string{"Info", "Warning", "Critical"}, r.Severity) {
		errs = append(errs, "Unknown severity.")
	}
	if r.Org != nil && s.org(*r.Org) == nil {
		errs = append(errs, "Organization not found.")
	}
	if r.Tag != nil && s.findTag(*r.Tag) == nil {
		errs = append(errs, "Tag not found.")
	}
	for _, c := range r.Channels {
		if s.findChannel(c) == nil {
			errs = append(errs, "Channel not found.")
			break
		}
	}
	if len(errs) > 0 {
		return nil, strings.Join(errs, " ")
	}
	return r, ""
}

func (s *Server) resolveRuleAlerts(rule uuid.UUID, forget bool) {
	now := time.Now().UTC()
	for _, a := range s.alerts {
		if a.Rule != nil && *a.Rule == rule {
			if a.Status != "Resolved" {
				a.Status, a.ResolvedAt = "Resolved", &now
			}
			if forget {
				a.Rule = nil
			}
		}
	}
}

func (s *Server) serveAlertRules(w http.ResponseWriter, r *http.Request, parts []string, body map[string]any) {
	s.seedRules()
	if !s.superAdmin() {
		problem(w, 403, "forbidden", "You do not have permission.")
		return
	}
	if r.Method == http.MethodGet && len(parts) == 2 && parts[1] == "types" {
		out := []map[string]any{}
		for _, t := range ruleTypes {
			m := map[string]any{"type": t, "thresholdUnit": nil, "thresholdMin": nil, "thresholdMax": nil, "thresholdDefault": nil,
				"supportsTag": endpointRule(t)}
			if spec, ok := ruleSpecs[t]; ok {
				m["thresholdUnit"], m["thresholdMin"], m["thresholdMax"], m["thresholdDefault"] = spec.unit, spec.min, spec.max, spec.initial
			}
			out = append(out, m)
		}
		reply(w, 200, out)
		return
	}
	if r.Method == http.MethodGet && len(parts) == 1 {
		list := slices.Clone(s.rules)
		slices.SortStableFunc(list, func(a, b *RuleInfo) int { return strings.Compare(a.Name, b.Name) })
		out := []map[string]any{}
		for _, rule := range list {
			out = append(out, s.ruleJSON(rule))
		}
		reply(w, 200, out)
		return
	}
	var cur *RuleInfo
	if len(parts) == 2 {
		id, _ := uuid.Parse(parts[1])
		i := slices.IndexFunc(s.rules, func(x *RuleInfo) bool { return x.ID == id })
		if i < 0 {
			problem(w, 404, "not_found", "Alert rule was not found.")
			return
		}
		cur = s.rules[i]
	}
	switch {
	case r.Method == http.MethodDelete && cur != nil:
		s.resolveRuleAlerts(cur.ID, true)
		s.rules = slices.DeleteFunc(s.rules, func(x *RuleInfo) bool { return x == cur })
		s.addAudit(AuditInfo{Username: s.actorName(), Org: cur.Org, Action: "alert_rule.delete", TargetType: "AlertRule", TargetID: cur.ID.String()})
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && cur == nil, r.Method == http.MethodPut && cur != nil:
		next, msg := s.ruleFrom(body)
		if next == nil {
			problem(w, 400, "validation_failed", msg)
			return
		}
		action := "alert_rule.create"
		if cur == nil {
			next.ID = uuid.New()
			s.rules = append(s.rules, next)
		} else {
			action = "alert_rule.update"
			scope := cur.Type != next.Type || !samePtr(cur.Threshold, next.Threshold) || !samePtr(cur.Org, next.Org) || !samePtr(cur.Tag, next.Tag)
			if scope || (cur.Enabled && !next.Enabled) {
				s.resolveRuleAlerts(cur.ID, false)
			}
			next.ID = cur.ID
			*cur = *next
			next = cur
		}
		s.addAudit(AuditInfo{Username: s.actorName(), Org: next.Org, Action: action, TargetType: "AlertRule", TargetID: next.ID.String()})
		reply(w, 200, s.ruleJSON(next))
	default:
		problem(w, 405, "", "")
	}
}

func samePtr[T comparable](a, b *T) bool {
	return (a == nil) == (b == nil) && (a == nil || *a == *b)
}

func (s *Server) findChannel(id uuid.UUID) *ChannelInfo {
	i := slices.IndexFunc(s.channels, func(c *ChannelInfo) bool { return c.ID == id })
	if i < 0 {
		return nil
	}
	return s.channels[i]
}

func (s *Server) channelJSON(c *ChannelInfo) map[string]any {
	var last any
	for _, d := range slices.Backward(s.deliveries) {
		if d.Channel == c.ID {
			last = map[string]any{"status": d.Status, "createdAt": d.CreatedAt, "lastError": nullable(d.LastError)}
			break
		}
	}
	emails := c.Emails
	if emails == nil {
		emails = []string{}
	}
	return map[string]any{"id": c.ID, "name": c.Name, "type": c.Type, "enabled": c.Enabled, "emailRecipients": emails, "webhookFormat": c.Format,
		"webhookHost": nullable(c.Host), "hasSigningSecret": c.Secret != "", "createdAt": c.CreatedAt, "updatedAt": c.UpdatedAt, "lastDelivery": last}
}

// applyChannel checks a channel as EasyPatch does and applies it to c; it
// returns a new signing secret when one was made, and the field and
// message of the first problem.
func applyChannel(c *ChannelInfo, body map[string]any, creating bool) (secret, field, msg string) {
	str := func(k string) string { v, _ := body[k].(string); return strings.TrimSpace(v) }
	name, typ := str("name"), str("type")
	switch {
	case name == "" || len([]rune(name)) > 100:
		return "", "name", "Name must be 1-100 characters."
	case typ != "Email" && typ != "Webhook":
		return "", "type", "Unknown channel type."
	case !creating && typ != c.Type:
		return "", "type", "The channel type cannot be changed."
	}
	var emails []string
	var u *url.URL
	if typ == "Email" {
		raw, _ := body["emailRecipients"].([]any)
		for _, e := range raw {
			v := strings.TrimSpace(e.(string))
			if v != "" && !slices.ContainsFunc(emails, func(x string) bool { return strings.EqualFold(x, v) }) {
				emails = append(emails, v)
			}
		}
		if len(emails) == 0 || len(emails) > 20 {
			return "", "emailRecipients", "Enter 1 to 20 email addresses."
		}
		for _, e := range emails {
			if a, err := mail.ParseAddress(e); err != nil || !strings.EqualFold(a.Address, e) {
				return "", "emailRecipients", "One of the email addresses is not valid."
			}
		}
	} else {
		if f := str("webhookFormat"); f != "Generic" && f != "Slack" && f != "Teams" {
			return "", "webhookFormat", "Choose Generic, Slack or Teams."
		}
		if _, given := body["webhookUrl"].(string); given || creating {
			var err error
			u, err = url.Parse(str("webhookUrl"))
			if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(str("webhookUrl")) > 2048 {
				return "", "webhookUrl", "Enter the https:// URL of the webhook."
			}
		}
	}
	c.Name, c.Type, c.UpdatedAt = name, typ, time.Now().UTC()
	c.Enabled, _ = body["enabled"].(bool)
	if typ == "Email" {
		c.Emails, c.Format, c.URL, c.Host, c.Secret = emails, nil, "", "", ""
		return "", "", ""
	}
	format := str("webhookFormat")
	c.Emails, c.Format = nil, &format
	if u != nil {
		c.URL, c.Host = u.String(), u.Hostname()
	}
	if format == "Generic" && c.Secret == "" {
		c.Secret = uuid.NewString()
		return c.Secret, "", ""
	}
	if format != "Generic" {
		c.Secret = ""
	}
	return "", "", ""
}

func (s *Server) serveChannels(w http.ResponseWriter, r *http.Request, parts []string, body map[string]any) {
	if !s.superAdmin() {
		problem(w, 403, "forbidden", "You do not have permission.")
		return
	}
	if r.Method == http.MethodGet && len(parts) == 2 {
		list := slices.Clone(s.channels)
		slices.SortStableFunc(list, func(a, b *ChannelInfo) int { return strings.Compare(a.Name, b.Name) })
		out := []map[string]any{}
		for _, c := range list {
			out = append(out, s.channelJSON(c))
		}
		reply(w, 200, out)
		return
	}
	if r.Method == http.MethodPost && len(parts) == 2 {
		now := time.Now().UTC()
		c := &ChannelInfo{ID: uuid.New(), CreatedAt: now}
		secret, field, msg := applyChannel(c, body, true)
		if field != "" {
			fields(w, map[string]string{field: msg})
			return
		}
		s.channels = append(s.channels, c)
		s.addAudit(AuditInfo{Username: s.actorName(), Action: "notifications.channel_create", TargetType: "NotificationChannel", TargetID: c.ID.String()})
		reply(w, 200, map[string]any{"channel": s.channelJSON(c), "signingSecret": nullable(secret)})
		return
	}
	id, _ := uuid.Parse(parts[2])
	c := s.findChannel(id)
	if c == nil {
		problem(w, 404, "not_found", "Channel was not found.")
		return
	}
	switch {
	case r.Method == http.MethodPut && len(parts) == 3:
		next := *c
		secret, field, msg := applyChannel(&next, body, false)
		if field != "" {
			fields(w, map[string]string{field: msg})
			return
		}
		*c = next
		s.addAudit(AuditInfo{Username: s.actorName(), Action: "notifications.channel_update", TargetType: "NotificationChannel", TargetID: c.ID.String()})
		reply(w, 200, map[string]any{"channel": s.channelJSON(c), "signingSecret": nullable(secret)})
	case r.Method == http.MethodDelete && len(parts) == 3:
		s.channels = slices.DeleteFunc(s.channels, func(x *ChannelInfo) bool { return x == c })
		s.deliveries = slices.DeleteFunc(s.deliveries, func(d *DeliveryInfo) bool { return d.Channel == c.ID })
		for _, rule := range s.rules {
			rule.Channels = slices.DeleteFunc(rule.Channels, func(x uuid.UUID) bool { return x == c.ID })
		}
		s.addAudit(AuditInfo{Username: s.actorName(), Action: "notifications.channel_delete", TargetType: "NotificationChannel", TargetID: c.ID.String()})
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && len(parts) == 4 && parts[3] == "rotate-secret":
		if c.Type != "Webhook" || c.Format == nil || *c.Format != "Generic" {
			problem(w, 400, "validation_failed", "Only generic webhooks have a signing secret.")
			return
		}
		c.Secret = uuid.NewString()
		reply(w, 200, map[string]any{"channel": s.channelJSON(c), "signingSecret": c.Secret})
	case r.Method == http.MethodPost && len(parts) == 4 && parts[3] == "test":
		now := time.Now().UTC()
		if slices.ContainsFunc(s.deliveries, func(d *DeliveryInfo) bool {
			return d.Channel == c.ID && d.Kind == "Test" && d.CreatedAt.After(now.Add(-30*time.Second))
		}) {
			problem(w, 429, "test_rate_limited", "A test was sent to this channel less than 30 seconds ago.")
			return
		}
		d := &DeliveryInfo{ID: uuid.New(), Channel: c.ID, Kind: "Test", Subject: "[EasyRMM] Test notification", Status: "Pending", CreatedAt: now}
		s.deliveries = append(s.deliveries, d)
		reply(w, 202, s.deliveryJSON(d))
	default:
		problem(w, 405, "", "")
	}
}

func (s *Server) deliveryJSON(d *DeliveryInfo) map[string]any {
	name := ""
	if c := s.findChannel(d.Channel); c != nil {
		name = c.Name
	}
	return map[string]any{"id": d.ID, "channelId": d.Channel, "channelName": name, "kind": d.Kind, "subject": d.Subject, "status": d.Status,
		"attempts": 0, "lastError": nullable(d.LastError), "createdAt": d.CreatedAt, "nextAttemptAt": d.CreatedAt, "sentAt": nil}
}

func (s *Server) serveDeliveries(w http.ResponseWriter, q url.Values, page, size int) {
	if !s.superAdmin() {
		problem(w, 403, "forbidden", "You do not have permission.")
		return
	}
	channel, _ := uuid.Parse(q.Get("channelId"))
	out := []map[string]any{}
	for _, d := range slices.Backward(s.deliveries) {
		if (channel == uuid.Nil || d.Channel == channel) && (q.Get("status") == "" || d.Status == q.Get("status")) {
			out = append(out, s.deliveryJSON(d))
		}
	}
	reply(w, 200, paged(out, page, min(size, 200)))
}
