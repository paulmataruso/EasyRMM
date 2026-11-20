package easypatch

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// EasyPatch's alerts and what raises and sends them:
// alerts, alert rules, notification channels and their deliveries.

// Alert is an alert EasyPatch raised. EndpointID is nil for an
// organization's alert (enrollment waiting, an update on hold).
type Alert struct {
	ID               uuid.UUID  `json:"id"`
	RuleID           *uuid.UUID `json:"ruleId"`
	RuleName         string     `json:"ruleName"`
	RuleType         string     `json:"ruleType"`
	Severity         string     `json:"severity"`
	Status           string     `json:"status"`
	Title            string     `json:"title"`
	Details          string     `json:"details"`
	OrganizationID   uuid.UUID  `json:"organizationId"`
	OrganizationName string     `json:"organizationName"`
	EndpointID       *uuid.UUID `json:"endpointId"`
	Hostname         string     `json:"hostname"`
	OpenedAt         time.Time  `json:"openedAt"`
	LastSeenAt       time.Time  `json:"lastSeenAt"`
	ResolvedAt       *time.Time `json:"resolvedAt"`
	AcknowledgedAt   *time.Time `json:"acknowledgedAt"`
	AcknowledgedBy   string     `json:"acknowledgedBy"`
}

// AlertFilter narrows EasyPatch's alerts. Status is unresolved (the
// default), open, acknowledged, resolved or all; the others are EasyPatch's
// names (Warning, EndpointOffline).
type AlertFilter struct {
	Status, Severity, RuleType, Search string
	OrganizationID, EndpointID         uuid.UUID
}

// Alerts reads a page of alerts: unresolved first, then the most severe,
// then the newest.
func (c *Client) Alerts(ctx context.Context, f AlertFilter, page, pageSize int) (Page[Alert], error) {
	q := url.Values{"page": {strconv.Itoa(page)}, "pageSize": {strconv.Itoa(pageSize)}}
	for k, v := range map[string]string{"status": f.Status, "severity": f.Severity, "ruleType": f.RuleType, "search": f.Search} {
		if v != "" {
			q.Set(k, v)
		}
	}
	if f.OrganizationID != uuid.Nil {
		q.Set("organizationId", f.OrganizationID.String())
	}
	if f.EndpointID != uuid.Nil {
		q.Set("endpointId", f.EndpointID.String())
	}
	var p Page[Alert]
	err := c.do(ctx, http.MethodGet, "/api/v1/alerts", q, nil, "", &p)
	return p, err
}

// AlertSummary counts the unresolved alerts: Open leaves out the
// acknowledged ones, and the severities count both.
type AlertSummary struct {
	Open         int `json:"open"`
	Acknowledged int `json:"acknowledged"`
	Critical     int `json:"critical"`
	Warning      int `json:"warning"`
	Info         int `json:"info"`
}

// AlertSummary counts the unresolved alerts of the statement's
// organizations.
func (c *Client) AlertSummary(ctx context.Context) (AlertSummary, error) {
	var s AlertSummary
	err := c.do(ctx, http.MethodGet, "/api/v1/alerts/summary", nil, nil, "", &s)
	return s, err
}

// AcknowledgeAlerts acknowledges the open alerts among ids (at most 500),
// and says how many it acknowledged.
func (c *Client) AcknowledgeAlerts(ctx context.Context, ids []uuid.UUID) (int, error) {
	var out struct {
		Acknowledged int `json:"acknowledged"`
	}
	err := c.do(ctx, http.MethodPost, "/api/v1/alerts/acknowledge", nil, map[string]any{"alertIds": ids}, "", &out)
	return out.Acknowledged, err
}

// AlertRuleType is what a type of rule looks at: the unit and bounds of its
// threshold (none when Unit is empty), and whether it looks at devices one
// by one, so that it can be limited to a tag.
type AlertRuleType struct {
	Type        string `json:"type"`
	Unit        string `json:"thresholdUnit"`
	Min         *int   `json:"thresholdMin"`
	Max         *int   `json:"thresholdMax"`
	Default     *int   `json:"thresholdDefault"`
	SupportsTag bool   `json:"supportsTag"`
}

// AlertRuleInput is a rule as EasyPatch takes it. Threshold is nil for a
// type without one; OrganizationID and TagID nil cover every organization
// and every device; RenotifyHours 0 never reminds.
type AlertRuleInput struct {
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

// AlertRule is a rule and how many of its alerts are unresolved.
type AlertRule struct {
	ID uuid.UUID `json:"id"`
	AlertRuleInput
	ThresholdUnit    string    `json:"thresholdUnit"`
	UnresolvedAlerts int       `json:"unresolvedAlerts"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

const alertRulesPath = "/api/v1/alert-rules"

// AlertRules lists the rules by name.
func (c *Client) AlertRules(ctx context.Context) ([]AlertRule, error) {
	var out []AlertRule
	err := c.do(ctx, http.MethodGet, alertRulesPath, nil, nil, "", &out)
	return out, err
}

// CreateAlertRule adds a rule.
func (c *Client) CreateAlertRule(ctx context.Context, in AlertRuleInput) (AlertRule, error) {
	var out AlertRule
	err := c.do(ctx, http.MethodPost, alertRulesPath, nil, in, "", &out)
	return out, err
}

// UpdateAlertRule changes a rule. EasyPatch resolves its alerts when its
// type, threshold or scope changes, or it is turned off.
func (c *Client) UpdateAlertRule(ctx context.Context, id uuid.UUID, in AlertRuleInput) (AlertRule, error) {
	var out AlertRule
	err := c.do(ctx, http.MethodPut, alertRulesPath+"/"+id.String(), nil, in, "", &out)
	return out, err
}

// DeleteAlertRule deletes a rule and resolves its alerts.
func (c *Client) DeleteAlertRule(ctx context.Context, id uuid.UUID) error {
	return c.do(ctx, http.MethodDelete, alertRulesPath+"/"+id.String(), nil, nil, "", nil)
}

// ChannelInput is a notification channel as EasyPatch takes it: email
// recipients for Email, a format (Generic, Slack or Teams) and an https URL
// for Webhook. A nil WebhookURL on a change keeps the stored one.
type ChannelInput struct {
	Name            string   `json:"name"`
	Type            string   `json:"type"`
	Enabled         bool     `json:"enabled"`
	EmailRecipients []string `json:"emailRecipients"`
	WebhookFormat   *string  `json:"webhookFormat"`
	WebhookURL      *string  `json:"webhookUrl"`
}

// DeliverySummary is the last message sent to a channel.
type DeliverySummary struct {
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"createdAt"`
	LastError string    `json:"lastError"`
}

// Channel is a notification channel. EasyPatch never gives a webhook's URL
// back, only its host; HasSigningSecret is a generic webhook's HMAC key.
type Channel struct {
	ID               uuid.UUID        `json:"id"`
	Name             string           `json:"name"`
	Type             string           `json:"type"`
	Enabled          bool             `json:"enabled"`
	EmailRecipients  []string         `json:"emailRecipients"`
	WebhookFormat    *string          `json:"webhookFormat"`
	WebhookHost      string           `json:"webhookHost"`
	HasSigningSecret bool             `json:"hasSigningSecret"`
	CreatedAt        time.Time        `json:"createdAt"`
	UpdatedAt        time.Time        `json:"updatedAt"`
	LastDelivery     *DeliverySummary `json:"lastDelivery"`
}

// ChannelSaved is a channel just saved, and the signing secret of a generic
// webhook when one was made: EasyPatch shows it this once.
type ChannelSaved struct {
	Channel       Channel `json:"channel"`
	SigningSecret string  `json:"signingSecret"`
}

// Delivery is a message to a channel: alerts opened, resolved or still
// open (a reminder), or a test.
type Delivery struct {
	ID            uuid.UUID  `json:"id"`
	ChannelID     uuid.UUID  `json:"channelId"`
	ChannelName   string     `json:"channelName"`
	Kind          string     `json:"kind"`
	Subject       string     `json:"subject"`
	Status        string     `json:"status"`
	Attempts      int        `json:"attempts"`
	LastError     string     `json:"lastError"`
	CreatedAt     time.Time  `json:"createdAt"`
	NextAttemptAt time.Time  `json:"nextAttemptAt"`
	SentAt        *time.Time `json:"sentAt"`
}

const channelsPath = "/api/v1/notifications/channels"

// Channels lists the notification channels by name.
func (c *Client) Channels(ctx context.Context) ([]Channel, error) {
	var out []Channel
	err := c.do(ctx, http.MethodGet, channelsPath, nil, nil, "", &out)
	return out, err
}

// CreateChannel adds a notification channel.
func (c *Client) CreateChannel(ctx context.Context, in ChannelInput) (ChannelSaved, error) {
	var out ChannelSaved
	err := c.do(ctx, http.MethodPost, channelsPath, nil, in, "", &out)
	return out, err
}

// UpdateChannel changes a notification channel; its type stays.
func (c *Client) UpdateChannel(ctx context.Context, id uuid.UUID, in ChannelInput) (ChannelSaved, error) {
	var out ChannelSaved
	err := c.do(ctx, http.MethodPut, channelsPath+"/"+id.String(), nil, in, "", &out)
	return out, err
}

// DeleteChannel deletes a channel, its deliveries, and its place in rules.
func (c *Client) DeleteChannel(ctx context.Context, id uuid.UUID) error {
	return c.do(ctx, http.MethodDelete, channelsPath+"/"+id.String(), nil, nil, "", nil)
}

// RotateChannelSecret gives a generic webhook a new signing secret.
func (c *Client) RotateChannelSecret(ctx context.Context, id uuid.UUID) (ChannelSaved, error) {
	var out ChannelSaved
	err := c.do(ctx, http.MethodPost, channelsPath+"/"+id.String()+"/rotate-secret", nil, nil, "", &out)
	return out, err
}

// TestChannel queues a test message to a channel; EasyPatch refuses a
// second within 30 seconds (429).
func (c *Client) TestChannel(ctx context.Context, id uuid.UUID) (Delivery, error) {
	var out Delivery
	err := c.do(ctx, http.MethodPost, channelsPath+"/"+id.String()+"/test", nil, nil, "", &out)
	return out, err
}

// Deliveries reads a page of the messages sent to channels, newest first:
// to one channel when channel is set, in one status (Pending, Sent,
// Failed) when status is.
func (c *Client) Deliveries(ctx context.Context, channel uuid.UUID, status string, page, pageSize int) (Page[Delivery], error) {
	q := url.Values{"page": {strconv.Itoa(page)}, "pageSize": {strconv.Itoa(pageSize)}}
	if channel != uuid.Nil {
		q.Set("channelId", channel.String())
	}
	if status != "" {
		q.Set("status", status)
	}
	var p Page[Delivery]
	err := c.do(ctx, http.MethodGet, "/api/v1/notifications/deliveries", q, nil, "", &p)
	return p, err
}
