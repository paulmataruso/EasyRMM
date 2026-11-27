package assets

import (
	"testing"
	"time"
)

func TestKeys(t *testing.T) {
	if got := SerialKey(" ab-12.c d"); got != "AB12CD" {
		t.Errorf("SerialKey = %q", got)
	}
	for in, want := range map[string]string{"Hewlett-Packard": "hp", "Dell Inc.": "dell", "LENOVO": "lenovo", "Acme Corporation": "acme"} {
		if got := MakerKey(in); got != want {
			t.Errorf("MakerKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestJudgements(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	day := func(s string) *time.Time {
		d, err := time.Parse(time.DateOnly, s)
		if err != nil {
			t.Fatal(err)
		}
		return &d
	}
	for in, want := range map[string]string{"2025-06-01": "ok", "2023-06-01": "aging", "2021-06-01": "end_of_life"} {
		if got := AgeStatus(day(in), DefaultAgePolicy, now); got != want {
			t.Errorf("AgeStatus(%s) = %q, want %q", in, got, want)
		}
	}
	if AgeStatus(nil, DefaultAgePolicy, now) != "" || WarrantyState(nil, now) != "" {
		t.Error("no date should give no judgement")
	}
	for in, want := range map[string]string{"2026-05-31": "expired", "2026-06-01": "expiring", "2026-08-30": "expiring", "2026-08-31": "active"} {
		if got := WarrantyState(day(in), now); got != want {
			t.Errorf("WarrantyState(%s) = %q, want %q", in, got, want)
		}
	}
}

func TestCheckValue(t *testing.T) {
	date, _ := fieldByName("purchase_date")
	if v, err := CheckValue(date, " 2024-02-29 "); err != nil || v != "2024-02-29" {
		t.Errorf("date: %q %v", v, err)
	}
	if _, err := CheckValue(date, "2023-02-29"); err == nil {
		t.Error("impossible date accepted")
	}
	status, _ := fieldByName("warranty_status")
	if _, err := CheckValue(status, "maybe"); err == nil {
		t.Error("unknown warranty status accepted")
	}
}

func TestEffectiveOrder(t *testing.T) {
	both := map[string]sourceValue{SourceAgent: {"A", "reported"}, SourceManual: {"M", "reported"}}
	serial, _ := fieldByName("serial_number")
	tag, _ := fieldByName("asset_tag")
	if got := effective(serial, both); got != "A" {
		t.Errorf("agent-first field = %q", got)
	}
	if got := effective(tag, both); got != "M" {
		t.Errorf("manual-first field = %q", got)
	}
	unknown := map[string]sourceValue{SourceAgent: {"", "unknown"}, SourceManual: {"M", "reported"}}
	if got := effective(serial, unknown); got != "M" {
		t.Errorf("unknown agent value decided: %q", got)
	}
}
