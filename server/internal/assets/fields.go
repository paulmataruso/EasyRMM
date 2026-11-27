package assets

import (
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
)

// Kinds an asset can be; the database lists the same.
var Kinds = []string{
	"workstation", "laptop", "server", "virtual_machine", "virtualization_host", "firewall", "router",
	"switch", "wireless_access_point", "network_device", "printer", "ups", "storage", "mobile_device",
	"internet_connection", "licence", "other",
}

// Statuses an asset can have, in the order of its life.
var Statuses = []string{"ordered", "in_stock", "in_use", "in_repair", "retired", "disposed", "lost"}

// WarrantyStatuses are what a vendor says of a warranty, entered by hand
// until a vendor source (feature 1) says it.
var WarrantyStatuses = []string{"", "active", "expired", "unknown"}

// Sources of a field's values.
const (
	SourceAgent  = "agent"
	SourceManual = "manual"
)

// Limits matching the database's.
const (
	MaxValueLength = 200
	MaxNotesLength = 4000
)

// Field is one entry of the catalog of fields an asset keeps a value for,
// per source.
type Field struct {
	Name string
	// Date fields are written YYYY-MM-DD.
	Date bool
	// Agent is true when the agent can report the field.
	Agent bool
	// ManualFirst puts a person's value ahead of the agent's.
	ManualFirst bool
	// Label is what the console calls it.
	Label string
}

// Catalog lists the fields in the order the console shows them.
var Catalog = []Field{
	{Name: "name", Agent: true, ManualFirst: true, Label: "Name"},
	{Name: "manufacturer", Agent: true, Label: "Manufacturer"},
	{Name: "model", Agent: true, Label: "Model"},
	{Name: "serial_number", Agent: true, Label: "Serial number"},
	{Name: "sku", Agent: true, Label: "SKU"},
	{Name: "chassis_type", Agent: true, Label: "Chassis type"},
	{Name: "asset_tag", Agent: true, ManualFirst: true, Label: "Asset tag"},
	{Name: "smbios_uuid", Agent: true, Label: "SMBIOS UUID"},
	{Name: "purchase_date", Date: true, Label: "Purchase date"},
	{Name: "warranty_expiry", Date: true, Label: "Warranty expires"},
	{Name: "warranty_status", Label: "Vendor warranty status"},
	{Name: "os_eol_date", Date: true, Label: "OS end of support"},
}

func fieldByName(name string) (Field, bool) {
	for _, f := range Catalog {
		if f.Name == name {
			return f, true
		}
	}
	return Field{}, false
}

// cleanValue makes a field's value safe to store: one line, trimmed.
func cleanValue(s string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			return ' '
		case r < 0x20 || r == 0x7f:
			return -1
		}
		return r
	}, s))
}

// CheckValue validates a manual value for a field, returning the value as
// it is stored.
func CheckValue(f Field, v string) (string, error) {
	v = cleanValue(v)
	switch {
	case utf8.RuneCountInString(v) > MaxValueLength:
		return "", apperr.Invalid(f.Name, "Use at most 200 characters.")
	case f.Date && v != "":
		if _, err := time.Parse(time.DateOnly, v); err != nil {
			return "", apperr.Invalid(f.Name, "Enter a date as YYYY-MM-DD.")
		}
	case f.Name == "warranty_status" && !slices.Contains(WarrantyStatuses, v):
		return "", apperr.Invalid(f.Name, "Choose active, expired or unknown.")
	}
	return v, nil
}

// SerialKey is the match key of a serial number: upper-cased, without
// spaces, dashes or dots. The one function every writer of serial_key uses.
func SerialKey(serial string) string {
	return strings.ToUpper(strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || r == '-' || r == '.' {
			return -1
		}
		return r
	}, serial))
}

var (
	makerSuffix = regexp.MustCompile(`\b(inc|corp|corporation|co|ltd|llc|gmbh)\b`)
	makerPunct  = regexp.MustCompile(`[^a-z0-9 ]+`)
	makerAlias  = map[string]string{"hewlett packard": "hp", "hewlettpackard": "hp", "hewlett packard enterprise": "hpe", "dell computer": "dell"}
)

// MakerKey is the match key of a manufacturer: lower-cased, without
// punctuation and company suffixes, with a few aliases folded.
func MakerKey(maker string) string {
	k := strings.ToLower(maker)
	k = strings.ReplaceAll(k, "-", " ")
	k = makerPunct.ReplaceAllString(k, "")
	k = makerSuffix.ReplaceAllString(k, "")
	k = strings.Join(strings.Fields(k), " ")
	if a, ok := makerAlias[k]; ok {
		return a
	}
	return k
}

// AgeStatus judges a purchase date against an organization's policy:
// "ok", "aging" or "end_of_life", empty when no date is known.
func AgeStatus(purchased *time.Time, p AgePolicy, now time.Time) string {
	if purchased == nil {
		return ""
	}
	switch {
	case !purchased.AddDate(0, p.EOLMonths, 0).After(now):
		return "end_of_life"
	case !purchased.AddDate(0, p.AgingMonths, 0).After(now):
		return "aging"
	}
	return "ok"
}

// WarrantyState judges a warranty expiry date: "active", "expiring" (within
// 90 days) or "expired", empty when none is recorded.
func WarrantyState(expiry *time.Time, now time.Time) string {
	if expiry == nil {
		return ""
	}
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	switch {
	case expiry.Before(today):
		return "expired"
	case expiry.Before(today.AddDate(0, 0, 91)):
		return "expiring"
	}
	return "active"
}

// effective picks the value that decides a field: the first reported,
// non-empty value in the order of the field's sources.
func effective(f Field, vals map[string]sourceValue) string {
	order := []string{SourceAgent, SourceManual}
	if f.ManualFirst {
		order = []string{SourceManual, SourceAgent}
	}
	for _, src := range order {
		if v, ok := vals[src]; ok && v.State == "reported" && v.Value != "" {
			return v.Value
		}
	}
	return ""
}

type sourceValue struct {
	Value string
	State string
}
