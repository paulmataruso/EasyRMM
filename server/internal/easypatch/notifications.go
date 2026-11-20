package easypatch

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"unicode"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Settings → Patching → Alert rules and Notifications: what raises
// EasyPatch's alerts, and where it sends them. Both are server-wide and the
// engine keeps them to its super administrators, so EasyRMM's super
// administrators read and change them.

// The limits EasyPatch puts on rules and channels.
const (
	maxRuleChannels   = 20
	maxRenotifyHours  = 720
	maxWebhookURL     = 2048
	deliveryPageSize  = 50
	maxDeliveryPage   = 10_000
	channelNameLength = 100
)

// The values EasyPatch's channels and deliveries take.
var (
	ChannelTypes      = []string{"Email", "Webhook"}
	WebhookFormats    = []string{"Generic", "Slack", "Teams"}
	DeliveryStatuses  = []string{"Pending", "Sent", "Failed"}
	orgAlertRuleKinds = []string{"EnrollmentPending", "UpdateHeld"}
)

// ruleThreshold is a rule type's threshold, as EasyPatch's catalog has it.
type ruleThreshold struct {
	unit              string
	min, max, initial int
}

var ruleThresholds = map[string]ruleThreshold{
	"EndpointOffline":       {"hours", 1, 720, 24},
	"SecurityUpdateMissing": {"days", 0, 365, 14},
	"RestartPending":        {"days", 1, 90, 7},
	"OsUnsupported":         {"days", 0, 365, 30},
}

// RuleTypes is every type of rule, as EasyPatch's /alert-rules/types lists
// them (the contract test holds the two together).
func RuleTypes() []AlertRuleType {
	out := make([]AlertRuleType, 0, len(AlertRuleKinds))
	for _, k := range AlertRuleKinds {
		t := AlertRuleType{Type: k, SupportsTag: !slices.Contains(orgAlertRuleKinds, k)}
		if th, ok := ruleThresholds[k]; ok {
			t.Unit, t.Min, t.Max, t.Default = th.unit, &th.min, &th.max, &th.initial
		}
		out = append(out, t)
	}
	return out
}

// notifications checks that the caller may read and change the rules and
// channels.
func (s *Service) notifications(ctx context.Context, c access.Caller) (*Client, error) {
	r, cl, err := s.conn(ctx)
	switch {
	case err != nil:
		return nil, err
	case r == nil:
		return nil, errNotConfigured
	case !c.CanGlobal(rbac.PermPatchConfigure):
		return nil, apperr.Forbidden()
	}
	return cl, nil
}

// ChannelRef is a channel as a rule names it.
type ChannelRef struct {
	ID      uuid.UUID `json:"id"`
	Name    string    `json:"name"`
	Type    string    `json:"type"`
	Enabled bool      `json:"enabled"`
}

// AlertRuleView is a rule with EasyRMM's organization and the tag's name.
type AlertRuleView struct {
	AlertRule
	// OrganizationID is EasyRMM's organization; nil covers every one, unless
	// UnlinkedOrganization says the rule covers an EasyPatch organization
	// EasyRMM does not link.
	OrganizationID       *uuid.UUID `json:"organizationId"`
	OrganizationName     string     `json:"organizationName,omitempty"`
	UnlinkedOrganization bool       `json:"unlinkedOrganization,omitempty"`
	TagName              string     `json:"tagName,omitempty"`
}

// AlertRuleList is the rules by name, the types of rule, and the channels a
// rule can send to.
type AlertRuleList struct {
	Items    []AlertRuleView `json:"items"`
	Types    []AlertRuleType `json:"types"`
	Channels []ChannelRef    `json:"channels"`
}

// ruleContext is what turns EasyPatch's rules into EasyRMM's: the linked
// organizations, tags and channels.
type ruleContext struct {
	orgs     []reportOrg
	tags     []Tag
	channels []Channel
}

func (s *Service) ruleContext(ctx context.Context, c access.Caller, cl *Client) (ruleContext, error) {
	var rc ruleContext
	orgs, err := s.linkedOrganizations(ctx, c, uuid.Nil)
	if err != nil {
		return rc, err
	}
	st := s.everywhere(ctx, c, RoleSuperAdmin)
	tags, err := cl.Tags(st)
	if err != nil {
		s.noteError(err)
		return rc, epError(err)
	}
	channels, err := cl.Channels(st)
	if err != nil {
		s.noteError(err)
		return rc, epError(err)
	}
	return ruleContext{orgs: orgs, tags: tags, channels: channels}, nil
}

func (rc ruleContext) view(r AlertRule) AlertRuleView {
	v := AlertRuleView{AlertRule: r}
	v.ChannelIDs = orEmpty(v.ChannelIDs)
	if ep := r.OrganizationID; ep != nil {
		if i := slices.IndexFunc(rc.orgs, func(o reportOrg) bool { return o.ep == *ep }); i >= 0 {
			v.OrganizationID, v.OrganizationName = &rc.orgs[i].id, rc.orgs[i].name
		} else {
			v.UnlinkedOrganization = true
		}
	}
	if r.TagID != nil {
		if i := slices.IndexFunc(rc.tags, func(t Tag) bool { return t.ID == *r.TagID }); i >= 0 {
			v.TagName = rc.tags[i].Name
		}
	}
	return v
}

// AlertRules lists EasyPatch's alert rules.
func (s *Service) AlertRules(ctx context.Context, c access.Caller) (AlertRuleList, error) {
	cl, err := s.notifications(ctx, c)
	if err != nil {
		return AlertRuleList{}, err
	}
	rules, err := cl.AlertRules(s.everywhere(ctx, c, RoleSuperAdmin))
	if err != nil {
		s.noteError(err)
		return AlertRuleList{}, epError(err)
	}
	rc, err := s.ruleContext(ctx, c, cl)
	if err != nil {
		return AlertRuleList{}, err
	}
	out := AlertRuleList{Items: []AlertRuleView{}, Types: RuleTypes(), Channels: []ChannelRef{}}
	for _, r := range rules {
		out.Items = append(out.Items, rc.view(r))
	}
	for _, ch := range rc.channels {
		out.Channels = append(out.Channels, ChannelRef{ID: ch.ID, Name: ch.Name, Type: ch.Type, Enabled: ch.Enabled})
	}
	return out, nil
}

// AlertRuleRequest is a rule as EasyRMM takes it: OrganizationID is
// EasyRMM's organization, nil for every one.
type AlertRuleRequest struct {
	Name            string      `json:"name"`
	Type            string      `json:"type"`
	Enabled         bool        `json:"enabled"`
	Severity        string      `json:"severity"`
	Threshold       *int        `json:"threshold"`
	OrganizationID  *uuid.UUID  `json:"organizationId"`
	TagID           *uuid.UUID  `json:"tagId"`
	ChannelIDs      []uuid.UUID `json:"channelIds"`
	NotifyOnResolve bool        `json:"notifyOnResolve"`
	RenotifyHours   int         `json:"renotifyHours"`
}

// ruleInput checks a rule as EasyPatch does, field by field, and turns it
// into EasyPatch's.
func (rc ruleContext) ruleInput(in AlertRuleRequest) (AlertRuleInput, error) {
	f := apperr.Fields{}
	name := strings.TrimSpace(in.Name)
	f.Check(name != "" && len([]rune(name)) <= 100 && !strings.ContainsFunc(name, unicode.IsControl), "name",
		"Give a name of 1 to 100 characters.")
	f.Check(slices.Contains(AlertRuleKinds, in.Type), "type", "Choose what the rule looks for.")
	f.Check(slices.Contains(AlertSeverities, in.Severity), "severity", "Choose a severity.")
	threshold := in.Threshold
	if th, ok := ruleThresholds[in.Type]; ok {
		f.Check(threshold != nil && *threshold >= th.min && *threshold <= th.max, "threshold",
			"Choose from "+itoa(th.min)+" to "+itoa(th.max)+" "+th.unit+".")
	} else {
		threshold = nil
	}
	f.Check(in.RenotifyHours >= 0 && in.RenotifyHours <= maxRenotifyHours, "renotifyHours",
		"Choose from 0 (never) to 720 hours.")
	out := AlertRuleInput{Name: name, Type: in.Type, Enabled: in.Enabled, Severity: in.Severity, Threshold: threshold,
		NotifyOnResolve: in.NotifyOnResolve, RenotifyHours: in.RenotifyHours, ChannelIDs: dedupe(in.ChannelIDs)}
	if in.OrganizationID != nil {
		i := slices.IndexFunc(rc.orgs, func(o reportOrg) bool { return o.id == *in.OrganizationID })
		f.Check(i >= 0, "organizationId", "Choose an organization in the patching engine.")
		if i >= 0 {
			out.OrganizationID = &rc.orgs[i].ep
		}
	}
	if in.TagID != nil {
		f.Check(!slices.Contains(orgAlertRuleKinds, in.Type), "tagId", "This rule looks at organizations, not devices: it cannot be limited to a tag.")
		f.Check(slices.ContainsFunc(rc.tags, func(t Tag) bool { return t.ID == *in.TagID }), "tagId", "Choose a tag.")
		out.TagID = in.TagID
	}
	f.Check(len(out.ChannelIDs) <= maxRuleChannels, "channelIds", "Choose at most 20 channels.")
	for _, id := range out.ChannelIDs {
		f.Check(slices.ContainsFunc(rc.channels, func(ch Channel) bool { return ch.ID == id }), "channelIds", "Choose channels that exist.")
	}
	return out, f.Err()
}

func ruleDetails(v AlertRuleView) map[string]any {
	d := map[string]any{"name": v.Name, "type": v.Type, "enabled": v.Enabled, "severity": v.Severity, "channels": len(v.ChannelIDs),
		"notifyOnResolve": v.NotifyOnResolve, "renotifyHours": v.RenotifyHours}
	if v.Threshold != nil {
		d["threshold"] = *v.Threshold
	}
	if v.OrganizationName != "" {
		d["organization"] = v.OrganizationName
	}
	if v.TagName != "" {
		d["tag"] = v.TagName
	}
	return d
}

func (s *Service) recordRule(ctx context.Context, c access.Caller, action string, v AlertRuleView) error {
	e := audit.Event{Actor: c.Actor, Action: action, TargetType: "easypatch_alert_rule", TargetID: v.ID.String(), Outcome: audit.Success,
		Details: ruleDetails(v)}
	if v.OrganizationID != nil {
		e.OrganizationID = *v.OrganizationID
	}
	return s.record(ctx, []audit.Event{e})
}

// CreateAlertRule adds an alert rule.
func (s *Service) CreateAlertRule(ctx context.Context, c access.Caller, in AlertRuleRequest) (AlertRuleView, error) {
	cl, err := s.notifications(ctx, c)
	if err != nil {
		return AlertRuleView{}, err
	}
	rc, err := s.ruleContext(ctx, c, cl)
	if err != nil {
		return AlertRuleView{}, err
	}
	input, err := rc.ruleInput(in)
	if err != nil {
		return AlertRuleView{}, err
	}
	r, err := cl.CreateAlertRule(s.everywhere(ctx, c, RoleSuperAdmin), input)
	if err != nil {
		s.noteError(err)
		return AlertRuleView{}, epError(err)
	}
	v := rc.view(r)
	return v, s.recordRule(ctx, c, "patch.alert_rule_create", v)
}

// UpdateAlertRule changes an alert rule. EasyPatch resolves its alerts when
// what it looks for or where changes, or it is turned off; the next check
// opens again those that still apply.
func (s *Service) UpdateAlertRule(ctx context.Context, c access.Caller, id uuid.UUID, in AlertRuleRequest) (AlertRuleView, error) {
	cl, err := s.notifications(ctx, c)
	if err != nil {
		return AlertRuleView{}, err
	}
	cur, rc, err := s.alertRule(ctx, c, cl, id)
	if err != nil {
		return AlertRuleView{}, err
	}
	if cur.UnlinkedOrganization && in.OrganizationID == nil {
		return AlertRuleView{}, apperr.Invalid("organizationId",
			"This rule covers a patching engine organization EasyRMM does not link: choose an organization.")
	}
	input, err := rc.ruleInput(in)
	if err != nil {
		return AlertRuleView{}, err
	}
	r, err := cl.UpdateAlertRule(s.everywhere(ctx, c, RoleSuperAdmin), id, input)
	if err != nil {
		s.noteError(err)
		return AlertRuleView{}, epError(err)
	}
	v := rc.view(r)
	return v, s.recordRule(ctx, c, "patch.alert_rule_update", v)
}

// DeleteAlertRule deletes an alert rule; EasyPatch resolves its alerts.
func (s *Service) DeleteAlertRule(ctx context.Context, c access.Caller, id uuid.UUID) error {
	cl, err := s.notifications(ctx, c)
	if err != nil {
		return err
	}
	cur, _, err := s.alertRule(ctx, c, cl, id)
	if err != nil {
		return err
	}
	if err := cl.DeleteAlertRule(s.everywhere(ctx, c, RoleSuperAdmin), id); err != nil {
		s.noteError(err)
		return epError(err)
	}
	return s.recordRule(ctx, c, "patch.alert_rule_delete", cur)
}

// alertRule reads a rule, as EasyPatch has no call for one.
func (s *Service) alertRule(ctx context.Context, c access.Caller, cl *Client, id uuid.UUID) (AlertRuleView, ruleContext, error) {
	rules, err := cl.AlertRules(s.everywhere(ctx, c, RoleSuperAdmin))
	if err != nil {
		s.noteError(err)
		return AlertRuleView{}, ruleContext{}, epError(err)
	}
	i := slices.IndexFunc(rules, func(r AlertRule) bool { return r.ID == id })
	if i < 0 {
		return AlertRuleView{}, ruleContext{}, apperr.NotFound()
	}
	rc, err := s.ruleContext(ctx, c, cl)
	if err != nil {
		return AlertRuleView{}, ruleContext{}, err
	}
	return rc.view(rules[i]), rc, nil
}

// MailView is the mail server email channels send through.
type MailView struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Security    string `json:"security"`
	FromAddress string `json:"fromAddress"`
	FromName    string `json:"fromName"`
}

// NotificationsView is EasyPatch's notification channels, the mail server
// its email channels use (EasyRMM's, given at each start), and whether
// webhooks may go to private networks.
type NotificationsView struct {
	Channels                    []Channel `json:"channels"`
	Mail                        MailView  `json:"mail"`
	AllowPrivateNetworkWebhooks bool      `json:"allowPrivateNetworkWebhooks"`
}

// Notifications reads EasyPatch's notification channels and settings.
func (s *Service) Notifications(ctx context.Context, c access.Caller) (NotificationsView, error) {
	cl, err := s.notifications(ctx, c)
	if err != nil {
		return NotificationsView{}, err
	}
	st := s.everywhere(ctx, c, RoleSuperAdmin)
	channels, err := cl.Channels(st)
	if err != nil {
		s.noteError(err)
		return NotificationsView{}, epError(err)
	}
	m, err := cl.MailSettings(st)
	if err != nil {
		s.noteError(err)
		return NotificationsView{}, epError(err)
	}
	for i := range channels {
		channels[i].EmailRecipients = orEmpty(channels[i].EmailRecipients)
	}
	return NotificationsView{Channels: orEmpty(channels), AllowPrivateNetworkWebhooks: m.AllowPrivateNetworkWebhooks,
		Mail: MailView{Host: m.SMTPHost, Port: m.SMTPPort, Security: m.SMTPSecurity, FromAddress: m.FromAddress, FromName: m.FromName}}, nil
}

// NotificationSettings is what EasyRMM changes of EasyPatch's notification
// settings: its mail server is EasyRMM's.
type NotificationSettings struct {
	AllowPrivateNetworkWebhooks bool `json:"allowPrivateNetworkWebhooks"`
}

// SetNotificationSettings changes whether webhooks may go to private
// networks, keeping the mail server as it is.
func (s *Service) SetNotificationSettings(ctx context.Context, c access.Caller, in NotificationSettings) (NotificationsView, error) {
	cl, err := s.notifications(ctx, c)
	if err != nil {
		return NotificationsView{}, err
	}
	st := s.everywhere(ctx, c, RoleSuperAdmin)
	m, err := cl.MailSettings(st)
	if err != nil {
		s.noteError(err)
		return NotificationsView{}, epError(err)
	}
	if m.AllowPrivateNetworkWebhooks != in.AllowPrivateNetworkWebhooks {
		// EasyPatch replaces its notification settings at once; a nil
		// password keeps the stored one.
		err := cl.SetMailSettings(st, MailSettingsInput{SMTPHost: m.SMTPHost, SMTPPort: m.SMTPPort, SMTPSecurity: m.SMTPSecurity,
			SMTPUsername: m.SMTPUsername, FromAddress: m.FromAddress, FromName: m.FromName, SMTPSkipCertificateCheck: m.SMTPSkipCertificateCheck,
			AllowPrivateNetworkWebhooks: in.AllowPrivateNetworkWebhooks})
		if err != nil {
			s.noteError(err)
			return NotificationsView{}, epError(err)
		}
		if err := s.record(ctx, []audit.Event{{Actor: c.Actor, Action: "patch.notifications_update", TargetType: "easypatch_notifications",
			TargetID: "settings", Outcome: audit.Success, Details: map[string]any{"changes": map[string]any{"allowPrivateNetworkWebhooks": map[string]any{
				"from": m.AllowPrivateNetworkWebhooks, "to": in.AllowPrivateNetworkWebhooks}}}}}); err != nil {
			return NotificationsView{}, err
		}
	}
	return s.Notifications(ctx, c)
}

// ChannelRequest is a channel as EasyRMM takes it.
type ChannelRequest = ChannelInput

// channelInput checks a channel as EasyPatch does. cur is the channel being
// changed, nil for a new one.
func channelInput(in ChannelRequest, cur *Channel) (ChannelInput, error) {
	f := apperr.Fields{}
	out := ChannelInput{Name: strings.TrimSpace(in.Name), Type: in.Type, Enabled: in.Enabled, EmailRecipients: []string{}}
	f.Check(out.Name != "" && len([]rune(out.Name)) <= channelNameLength && !strings.ContainsFunc(out.Name, unicode.IsControl), "name",
		"Give a name of 1 to 100 characters.")
	switch {
	case !slices.Contains(ChannelTypes, in.Type):
		f.Add("type", "Choose email or a webhook.")
	case cur != nil && cur.Type != in.Type:
		f.Add("type", "A channel's type cannot change: add a new channel.")
	case in.Type == "Email":
		to, err := validRecipients(in.EmailRecipients, true)
		if ae, ok := apperr.As(err); ok {
			for _, msg := range ae.Fields {
				f.Add("emailRecipients", msg)
			}
		}
		out.EmailRecipients = to
	default:
		if in.WebhookFormat == nil || !slices.Contains(WebhookFormats, *in.WebhookFormat) {
			f.Add("webhookFormat", "Choose Generic, Slack or Teams.")
		}
		out.WebhookFormat = in.WebhookFormat
		if in.WebhookURL != nil || cur == nil {
			raw := ""
			if in.WebhookURL != nil {
				raw = strings.TrimSpace(*in.WebhookURL)
			}
			u, err := url.Parse(raw)
			f.Check(err == nil && raw != "" && len(raw) <= maxWebhookURL && u.Scheme == "https" && u.Host != "" && u.User == nil, "webhookUrl",
				"Enter the webhook's https:// address.")
			out.WebhookURL = &raw
		}
	}
	return out, f.Err()
}

// channelDetails is what EasyRMM's audit log keeps of a channel: never a
// webhook's address, which is often its secret.
func channelDetails(ch Channel) map[string]any {
	d := map[string]any{"name": ch.Name, "type": ch.Type, "enabled": ch.Enabled}
	if ch.Type == "Email" {
		d["recipients"] = len(ch.EmailRecipients)
	} else {
		d["host"] = ch.WebhookHost
		if ch.WebhookFormat != nil {
			d["format"] = *ch.WebhookFormat
		}
	}
	return d
}

func (s *Service) recordChannel(ctx context.Context, c access.Caller, action string, ch Channel, extra map[string]any) error {
	d := channelDetails(ch)
	for k, v := range extra {
		d[k] = v
	}
	return s.record(ctx, []audit.Event{{Actor: c.Actor, Action: action, TargetType: "easypatch_channel", TargetID: ch.ID.String(),
		Outcome: audit.Success, Details: d}})
}

// CreateChannel adds a notification channel. A generic webhook's signing
// secret is in the answer, this once.
func (s *Service) CreateChannel(ctx context.Context, c access.Caller, in ChannelRequest) (ChannelSaved, error) {
	cl, err := s.notifications(ctx, c)
	if err != nil {
		return ChannelSaved{}, err
	}
	input, err := channelInput(in, nil)
	if err != nil {
		return ChannelSaved{}, err
	}
	saved, err := cl.CreateChannel(s.everywhere(ctx, c, RoleSuperAdmin), input)
	if err != nil {
		s.noteError(err)
		return ChannelSaved{}, epError(err)
	}
	saved.Channel.EmailRecipients = orEmpty(saved.Channel.EmailRecipients)
	return saved, s.recordChannel(ctx, c, "patch.channel_create", saved.Channel, nil)
}

// channel reads a channel, as EasyPatch has no call for one.
func (s *Service) channel(ctx context.Context, c access.Caller, cl *Client, id uuid.UUID) (Channel, error) {
	channels, err := cl.Channels(s.everywhere(ctx, c, RoleSuperAdmin))
	if err != nil {
		s.noteError(err)
		return Channel{}, epError(err)
	}
	i := slices.IndexFunc(channels, func(ch Channel) bool { return ch.ID == id })
	if i < 0 {
		return Channel{}, apperr.NotFound()
	}
	return channels[i], nil
}

// UpdateChannel changes a notification channel. A webhook keeps its address
// unless a new one is given; one becoming a generic webhook gets a signing
// secret, in the answer.
func (s *Service) UpdateChannel(ctx context.Context, c access.Caller, id uuid.UUID, in ChannelRequest) (ChannelSaved, error) {
	cl, err := s.notifications(ctx, c)
	if err != nil {
		return ChannelSaved{}, err
	}
	cur, err := s.channel(ctx, c, cl, id)
	if err != nil {
		return ChannelSaved{}, err
	}
	input, err := channelInput(in, &cur)
	if err != nil {
		return ChannelSaved{}, err
	}
	saved, err := cl.UpdateChannel(s.everywhere(ctx, c, RoleSuperAdmin), id, input)
	if err != nil {
		s.noteError(err)
		return ChannelSaved{}, epError(err)
	}
	saved.Channel.EmailRecipients = orEmpty(saved.Channel.EmailRecipients)
	return saved, s.recordChannel(ctx, c, "patch.channel_update", saved.Channel, map[string]any{"addressChanged": input.WebhookURL != nil})
}

// DeleteChannel deletes a notification channel; EasyPatch takes it out of
// the rules that send to it.
func (s *Service) DeleteChannel(ctx context.Context, c access.Caller, id uuid.UUID) error {
	cl, err := s.notifications(ctx, c)
	if err != nil {
		return err
	}
	cur, err := s.channel(ctx, c, cl, id)
	if err != nil {
		return err
	}
	if err := cl.DeleteChannel(s.everywhere(ctx, c, RoleSuperAdmin), id); err != nil {
		s.noteError(err)
		return epError(err)
	}
	return s.recordChannel(ctx, c, "patch.channel_delete", cur, nil)
}

// RotateChannelSecret gives a generic webhook a new signing secret, in the
// answer this once; the old one stops working.
func (s *Service) RotateChannelSecret(ctx context.Context, c access.Caller, id uuid.UUID) (ChannelSaved, error) {
	cl, err := s.notifications(ctx, c)
	if err != nil {
		return ChannelSaved{}, err
	}
	cur, err := s.channel(ctx, c, cl, id)
	if err != nil {
		return ChannelSaved{}, err
	}
	if cur.Type != "Webhook" || cur.WebhookFormat == nil || *cur.WebhookFormat != "Generic" {
		return ChannelSaved{}, apperr.Conflict("easypatch_no_secret", "Only generic webhooks have a signing secret.")
	}
	saved, err := cl.RotateChannelSecret(s.everywhere(ctx, c, RoleSuperAdmin), id)
	if err != nil {
		s.noteError(err)
		return ChannelSaved{}, epError(err)
	}
	saved.Channel.EmailRecipients = orEmpty(saved.Channel.EmailRecipients)
	return saved, s.recordChannel(ctx, c, "patch.channel_rotate_secret", saved.Channel, nil)
}

// errTestTooSoon is EasyPatch refusing a second test within 30 seconds.
var errTestTooSoon = apperr.Conflict("easypatch_test_too_soon", "A test went to this channel less than 30 seconds ago: wait a moment, then send another.")

// TestChannel has EasyPatch send a test message to a channel, the way it
// sends alerts; the deliveries show how it went.
func (s *Service) TestChannel(ctx context.Context, c access.Caller, id uuid.UUID) (Delivery, error) {
	cl, err := s.notifications(ctx, c)
	if err != nil {
		return Delivery{}, err
	}
	cur, err := s.channel(ctx, c, cl, id)
	if err != nil {
		return Delivery{}, err
	}
	d, err := cl.TestChannel(s.everywhere(ctx, c, RoleSuperAdmin), id)
	switch {
	case IsStatus(err, http.StatusTooManyRequests):
		return Delivery{}, errTestTooSoon
	case err != nil:
		s.noteError(err)
		return Delivery{}, epError(err)
	}
	return d, s.recordChannel(ctx, c, "patch.channel_test", cur, nil)
}

// DeliveriesQuery narrows the deliveries: to a channel, and a status.
type DeliveriesQuery struct {
	ChannelID uuid.UUID
	Status    string
	Page      int
}

// DeliveryPage is a page of deliveries, newest first.
type DeliveryPage struct {
	Items      []Delivery `json:"items"`
	Page       int        `json:"page"`
	PageSize   int        `json:"pageSize"`
	TotalCount int        `json:"totalCount"`
}

// Deliveries lists the messages EasyPatch sent, or is sending, to its
// channels.
func (s *Service) Deliveries(ctx context.Context, c access.Caller, q DeliveriesQuery) (DeliveryPage, error) {
	switch {
	case q.Status != "" && !slices.Contains(DeliveryStatuses, q.Status):
		return DeliveryPage{}, apperr.Invalid("status", "Choose pending, sent or failed.")
	case q.Page < 1 || q.Page > maxDeliveryPage:
		return DeliveryPage{}, apperr.Invalid("page", "Choose a page from 1 to 10,000.")
	}
	cl, err := s.notifications(ctx, c)
	if err != nil {
		return DeliveryPage{}, err
	}
	p, err := cl.Deliveries(s.everywhere(ctx, c, RoleSuperAdmin), q.ChannelID, q.Status, q.Page, deliveryPageSize)
	if err != nil {
		s.noteError(err)
		return DeliveryPage{}, epError(err)
	}
	return DeliveryPage{Items: orEmpty(p.Items), Page: q.Page, PageSize: deliveryPageSize, TotalCount: p.TotalCount}, nil
}
