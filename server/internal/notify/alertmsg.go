package notify

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"golang.org/x/text/unicode/norm"

	"github.com/paulmataruso/easyrmm/server/internal/mailer"
)

// What an alert or a site outage looks like in a message, and how values
// that come from agents and people are made safe (ADR-0053, "Content").

// Limits of names in messages.
const (
	DeviceNameClip = 64
	OSClip         = 100
	OtherNameClip  = 100
	// EmailAlerts is how many alerts an email lists; the rest is a count.
	EmailAlerts = 25
	// WebhookAlerts is how many alerts one webhook delivery carries.
	WebhookAlerts = 100
)

// Clean normalises a value to NFKC, reads the ideographic full stops as dots,
// removes control, format, line and paragraph separator characters and clips
// it to n characters with an ellipsis.
func Clean(s string, n int) string {
	s = norm.NFKC.String(s)
	s = strings.NewReplacer("。", ".", "｡", ".", "．", ".").Replace(s)
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return -1
		}
		return r
	}, s)
	return clip(s, n)
}

var linkable = regexp.MustCompile(`(?i)(^|[^a-z0-9])[a-z][a-z0-9+.-]*://|(^|[^a-z0-9])www\.|[a-z0-9-]+\.[a-z]{2,}([^a-z]|$)|@`)

// Defang makes a value one that no mail client links: a value holding a
// scheme and "://", a www name, a dotted name ending in letters or an email
// address has its dots, at signs and "://" bracketed.
func Defang(s string) string {
	if !linkable.MatchString(s) {
		return s
	}
	s = strings.ReplaceAll(s, "://", "[://]")
	s = strings.ReplaceAll(s, ".", "[.]")
	return strings.ReplaceAll(s, "@", "[@]")
}

// AlertItem is an alert as a message carries it: its incident's ID, stable
// from opened to resolved and across a policy change.
type AlertItem struct {
	ID             uuid.UUID  `json:"id"`
	AlertID        uuid.UUID  `json:"alertId"`
	Key            string     `json:"key"`
	Kind           string     `json:"kind"`
	Check          string     `json:"check,omitempty"`
	Name           string     `json:"name"`
	Severity       string     `json:"severity"`
	Status         string     `json:"status"`
	Value          float64    `json:"value"`
	Detail         string     `json:"detail,omitempty"`
	Subject        string     `json:"subject,omitempty"`
	DeviceID       uuid.UUID  `json:"deviceId"`
	Device         string     `json:"device"`
	SiteID         uuid.UUID  `json:"siteId"`
	Site           string     `json:"site"`
	OrganizationID uuid.UUID  `json:"organizationId"`
	Organization   string     `json:"organization"`
	OpenedAt       time.Time  `json:"openedAt"`
	AcknowledgedAt *time.Time `json:"acknowledgedAt,omitempty"`
	AcknowledgedBy string     `json:"acknowledgedBy,omitempty"`
	ResolvedAt     *time.Time `json:"resolvedAt,omitempty"`
	Resolution     string     `json:"resolution,omitempty"`
}

// OutageItem is a site outage as a message carries it.
type OutageItem struct {
	ID             uuid.UUID   `json:"id"`
	SiteID         uuid.UUID   `json:"siteId"`
	Site           string      `json:"site"`
	OrganizationID uuid.UUID   `json:"organizationId"`
	Devices        int         `json:"devices"`
	Back           int         `json:"back,omitempty"`
	StartedAt      time.Time   `json:"startedAt"`
	EndedAt        *time.Time  `json:"endedAt,omitempty"`
	AlertIDs       []uuid.UUID `json:"alertIds,omitempty"`
}

// Digest is what a channel read by people is sent, with sections (ADR-0053,
// "Digests"). What the planner queues for the channel merges into the one
// waiting.
type Digest struct {
	Down     []OutageItem `json:"down,omitempty"`
	Up       []OutageItem `json:"up,omitempty"`
	New      []AlertItem  `json:"new,omitempty"`
	Resolved []AlertItem  `json:"resolved,omitempty"`
	Open     []AlertItem  `json:"open,omitempty"`
	Notices  []NoticeBody `json:"notices,omitempty"`
}

func (d *Digest) empty() bool {
	return len(d.Down)+len(d.Up)+len(d.New)+len(d.Resolved)+len(d.Open)+len(d.Notices) == 0
}

func without(items []AlertItem, id uuid.UUID) ([]AlertItem, bool) {
	out := items[:0:0]
	found := false
	for _, it := range items {
		if it.ID == id {
			found = true
			continue
		}
		out = append(out, it)
	}
	return out, found
}

// Event names a webhook receives.
const (
	EventAlertOpened       = "alerts.opened"
	EventAlertResolved     = "alerts.resolved"
	EventAlertAcknowledged = "alerts.acknowledged"
	EventAlertReminder     = "alerts.reminder"
	EventSiteOffline       = "sites.offline"
	EventSiteOnline        = "sites.online"
	EventNoticeOpened      = "notices.opened"
	EventNoticeResolved    = "notices.resolved"
	EventDigest            = "digest"
)

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }

func sev(s string) string {
	if s == "critical" {
		return "Critical"
	}
	return "Warning"
}

// alertLine is one alert as a sentence, defanged for email.
func alertLine(a AlertItem, verb string, at time.Time) string {
	what := Defang(a.Name)
	where := Defang(a.Device)
	if a.Subject != "" {
		where += " (" + Defang(Clean(a.Subject, OtherNameClip)) + ")"
	}
	return fmt.Sprintf("%s: %s on %s at %s, %s %s.", sev(a.Severity), what, where, Defang(a.Site), verb, stamp(at))
}

func section(title string, lines []string, limit int) []string {
	if len(lines) == 0 {
		return nil
	}
	out := []string{title}
	if len(lines) > limit {
		out = append(out, lines[:limit]...)
		return append(out, fmt.Sprintf("…and %d more.", len(lines)-limit))
	}
	return append(out, lines...)
}

// subjectOf is a digest's subject line: EasyRMM's own words and numbers.
func (d *Digest) subjectLine() string {
	var parts []string
	add := func(n int, w string) {
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, w))
		}
	}
	add(len(d.Down), "site down")
	add(len(d.Up), "site back")
	add(len(d.New), "new")
	add(len(d.Resolved), "resolved")
	add(len(d.Open), "still open")
	add(len(d.Notices), "notices")
	if len(parts) == 0 {
		return "EasyRMM alerts"
	}
	return "EasyRMM alerts: " + strings.Join(parts, ", ")
}

// letter renders a digest as an email, with a link to the console when its
// address is known. Values are cleaned when the item is made and defanged
// here.
func (d *Digest) letter(consoleURL string) mailer.Letter {
	var before []string
	var lines []string
	for _, o := range d.Down {
		lines = append(lines, fmt.Sprintf("%s: all %d devices offline since %s.", Defang(o.Site), o.Devices, stamp(o.StartedAt)))
	}
	before = append(before, section("Sites offline", lines, EmailAlerts)...)
	lines = nil
	for _, o := range d.Up {
		at := o.StartedAt
		if o.EndedAt != nil {
			at = *o.EndedAt
		}
		lines = append(lines, fmt.Sprintf("%s is back online: %d of %d devices, at %s.", Defang(o.Site), o.Back, o.Devices, stamp(at)))
	}
	before = append(before, section("Sites back online", lines, EmailAlerts)...)
	lines = nil
	for _, a := range d.New {
		lines = append(lines, alertLine(a, "opened", a.OpenedAt))
	}
	before = append(before, section("New alerts", lines, EmailAlerts)...)
	lines = nil
	for _, a := range d.Resolved {
		at := a.OpenedAt
		if a.ResolvedAt != nil {
			at = *a.ResolvedAt
		}
		lines = append(lines, alertLine(a, "resolved", at))
	}
	before = append(before, section("Resolved alerts", lines, EmailAlerts)...)
	lines = nil
	for _, a := range d.Open {
		lines = append(lines, alertLine(a, "open since", a.OpenedAt))
	}
	before = append(before, section("Still open", lines, EmailAlerts)...)
	lines = nil
	for _, n := range d.Notices {
		lines = append(lines, Defang(n.Title)+".")
	}
	before = append(before, section("Notices", lines, EmailAlerts)...)
	l := mailer.Letter{Subject: d.subjectLine(), Before: before}
	if consoleURL != "" {
		l.Link = &mailer.Link{Label: "Open the alerts", URL: strings.TrimRight(consoleURL, "/") + "/alerts"}
	}
	return l
}
