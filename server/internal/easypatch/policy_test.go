package easypatch

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
)

func fieldErrs(t *testing.T, err error) map[string]string {
	t.Helper()
	var ae *apperr.Error
	if err == nil {
		return nil
	}
	if !errors.As(err, &ae) || ae.Kind != apperr.KindInvalid {
		t.Fatalf("want a validation error, got %v", err)
	}
	return ae.Fields
}

func TestResolvePolicyDefaults(t *testing.T) {
	p, from := resolvePolicy(nil)
	if *p.ScanIntervalMinutes != 360 || *p.AutoInstallEnabled || len(p.MaintenanceDays) != 0 || *p.MaintenanceStart != "02:00" ||
		!slices.Equal(p.AllowedCategories, []string{"Security", "Critical", "Cumulative", "Definition", "ServicingStack", "DotNet", "Other"}) ||
		p.ExcludedKbs == nil || p.WindowsUpdate == nil || p.ApplicationUpdates == nil {
		t.Fatalf("defaults: %+v", p)
	}
	for _, k := range []string{"scanIntervalMinutes", "allowedCategories", "maintenanceDays", "restartSchedule", "windowsUpdate.featureUpdates"} {
		if from[k] != "EasyPatch's defaults" {
			t.Errorf("%s from %q", k, from[k])
		}
	}
	if _, ok := from["excludedKbs"]; ok {
		t.Error("excluded KBs add up and have no single source")
	}
}

// The layers resolve as EasyPatch's PolicyResolver does: a plain value from
// the last layer that sets it, the window, the restart schedule, application
// updates and each Windows Update group as a unit, and excluded KBs added up.
func TestResolvePolicyLayers(t *testing.T) {
	defaults := PolicyLayer{ScanIntervalMinutes: ptr(120), ExcludedKbs: []string{"kb2"},
		WindowsUpdate: &LayerWindowsUpdate{QualityUpdates: &GroupSetting[QualityUpdates]{Managed: true, Value: &QualityUpdates{DeferDays: ptr(3)}}}}
	org := PolicyLayer{AutoInstallEnabled: ptr(true), MaintenanceDays: []int{1, 3}, MaintenanceStart: ptr("01:00"), ExcludedKbs: []string{"KB1"},
		ApplicationUpdates: &ApplicationUpdates{Enabled: true, ApprovedApps: []string{"Mozilla.Firefox"}}}
	site := PolicyLayer{ScanIntervalMinutes: ptr(60), WindowsUpdate: &LayerWindowsUpdate{QualityUpdates: &GroupSetting[QualityUpdates]{Managed: false}},
		ExcludedKbs: []string{"KB2", "nope"}}
	tag := PolicyLayer{MaintenanceDays: []int{6}, RestartSchedule: &RestartSchedule{Enabled: true, Days: []int{0}, Time: "04:00"}}
	p, from := resolvePolicy([]namedLayer{{"Default policy", defaults}, {"Organization", org}, {"Site", site}, {"Tag Ring 1", tag}})
	switch {
	case *p.ScanIntervalMinutes != 60 || from["scanIntervalMinutes"] != "Site":
		t.Errorf("scan: %d from %s", *p.ScanIntervalMinutes, from["scanIntervalMinutes"])
	case !*p.AutoInstallEnabled || from["autoInstallEnabled"] != "Organization":
		t.Errorf("auto-install from %s", from["autoInstallEnabled"])
	// The tag's window replaces the organization's whole: its start and
	// length are the defaults, not the organization's.
	case !slices.Equal(p.MaintenanceDays, []int{6}) || *p.MaintenanceStart != "02:00" || *p.MaintenanceDurationMinutes != 180 ||
		from["maintenanceDays"] != "Tag Ring 1":
		t.Errorf("window: %v %s %d from %s", p.MaintenanceDays, *p.MaintenanceStart, *p.MaintenanceDurationMinutes, from["maintenanceDays"])
	case p.WindowsUpdate.QualityUpdates == nil || p.WindowsUpdate.QualityUpdates.Managed || from["windowsUpdate.qualityUpdates"] != "Site":
		t.Errorf("quality updates: %+v from %s", p.WindowsUpdate.QualityUpdates, from["windowsUpdate.qualityUpdates"])
	case !slices.Equal(p.ExcludedKbs, []string{"KB2", "KB1"}):
		t.Errorf("excluded: %v", p.ExcludedKbs)
	case p.RestartSchedule == nil || p.RestartSchedule.Time != "04:00" || from["restartSchedule"] != "Tag Ring 1":
		t.Errorf("restart schedule: %+v", p.RestartSchedule)
	case !p.ApplicationUpdates.Enabled || from["applicationUpdates"] != "Organization":
		t.Errorf("application updates: %+v", p.ApplicationUpdates)
	case from["allowedCategories"] != "EasyPatch's defaults" || from["jitterPercent"] != "EasyPatch's defaults":
		t.Errorf("untouched values: %v", from)
	}
}

func TestNormalizePolicy(t *testing.T) {
	inherited, _ := resolvePolicy(nil)
	cases := []struct {
		name  string
		level string
		p     PolicyLayer
		field string
		text  string
	}{
		{"check-in", LevelOrganization, PolicyLayer{CheckInIntervalSeconds: ptr(5)}, "checkInIntervalSeconds", "from 15 to 3600"},
		{"scan", LevelOrganization, PolicyLayer{ScanIntervalMinutes: ptr(20000)}, "scanIntervalMinutes", "from 30 to 10080"},
		{"security delay", LevelSite, PolicyLayer{SecurityInstallDelayDays: ptr(91)}, "securityInstallDelayDays", "from 0 to 90"},
		{"no category", LevelOrganization, PolicyLayer{AllowedCategories: []string{}}, "allowedCategories", "at least one"},
		{"application category", LevelOrganization, PolicyLayer{AllowedCategories: []string{"Application"}}, "allowedCategories", "not a category"},
		{"bad day", LevelOrganization, PolicyLayer{MaintenanceDays: []int{7}}, "maintenanceDays", "0 (Sunday) to 6"},
		{"start without days", LevelOrganization, PolicyLayer{MaintenanceStart: ptr("03:00")}, "maintenanceDays", "with its start"},
		{"bad start", LevelOrganization, PolicyLayer{MaintenanceDays: []int{1}, MaintenanceStart: ptr("25:00")}, "maintenanceStart", "02:00"},
		{"auto-install with no window", LevelOrganization, PolicyLayer{AutoInstallEnabled: ptr(true)}, "maintenanceDays", "maintenance window"},
		{"window removed under auto-install", LevelDevice, PolicyLayer{AutoInstallEnabled: ptr(true), MaintenanceDays: []int{}}, "maintenanceDays", "maintenance window"},
		{"device site limit", LevelDevice, PolicyLayer{MaxConcurrentInstallsPerSite: ptr(5)}, "maxConcurrentInstallsPerSite", "Only the default"},
		{"tag site limit", LevelTag, PolicyLayer{MaxConcurrentInstallsPerSite: ptr(5)}, "maxConcurrentInstallsPerSite", "Only the default"},
		{"tag empty window", LevelTag, PolicyLayer{AutoInstallEnabled: ptr(true), MaintenanceDays: []int{}}, "maintenanceDays", "maintenance window"},
		{"bad KB", LevelOrganization, PolicyLayer{ExcludedKbs: []string{"KB12a"}}, "excludedKbs", "KB5044284"},
		{"bad winget id", LevelOrganization, PolicyLayer{ApplicationUpdates: &ApplicationUpdates{ApprovedApps: []string{"firefox"}}}, "applicationUpdates", "winget"},
		{"restart with no day", LevelOrganization, PolicyLayer{RestartSchedule: &RestartSchedule{Enabled: true}}, "restartSchedule", "at least one day"},
		{"restart time", LevelOrganization, PolicyLayer{RestartSchedule: &RestartSchedule{Enabled: true, Days: []int{1}, Time: "3am"}}, "restartSchedule", "03:00"},
		{"restart countdown", LevelOrganization, PolicyLayer{RestartSchedule: &RestartSchedule{Enabled: true, Days: []int{1}, Mode: "Countdown", CountdownMinutes: 90}},
			"restartSchedule", "1 to 60"},
		{"restart mode", LevelOrganization, PolicyLayer{RestartSchedule: &RestartSchedule{Enabled: true, Days: []int{1}, Mode: "Whenever"}}, "restartSchedule", "how the people"},
		{"restart expiry", LevelOrganization, PolicyLayer{RestartSchedule: &RestartSchedule{Enabled: true, Days: []int{1}, ExpiryMinutes: 2000}}, "restartSchedule", "24 hours"},
		{"managed with nothing", LevelOrganization, PolicyLayer{WindowsUpdate: &LayerWindowsUpdate{AutomaticUpdates: &GroupSetting[AutomaticUpdates]{Managed: true}}},
			"windowsUpdate.automaticUpdates", "Choose the settings"},
		{"automatic mode", LevelOrganization, PolicyLayer{WindowsUpdate: &LayerWindowsUpdate{AutomaticUpdates: &GroupSetting[AutomaticUpdates]{Managed: true,
			Value: &AutomaticUpdates{Mode: "Sometimes"}}}}, "windowsUpdate.automaticUpdates", "how Windows"},
		{"automatic hour", LevelOrganization, PolicyLayer{WindowsUpdate: &LayerWindowsUpdate{AutomaticUpdates: &GroupSetting[AutomaticUpdates]{Managed: true,
			Value: &AutomaticUpdates{Mode: "Disabled", ScheduledInstallHour: 24}}}}, "windowsUpdate.automaticUpdates", "0 to 23"},
		{"pin half", LevelOrganization, PolicyLayer{WindowsUpdate: &LayerWindowsUpdate{FeatureUpdates: &GroupSetting[FeatureUpdates]{Managed: true,
			Value: &FeatureUpdates{TargetProductVersion: "Windows 11"}}}}, "windowsUpdate.featureUpdates", "both the product"},
		{"pin product", LevelOrganization, PolicyLayer{WindowsUpdate: &LayerWindowsUpdate{FeatureUpdates: &GroupSetting[FeatureUpdates]{Managed: true,
			Value: &FeatureUpdates{TargetProductVersion: "Windows 12", TargetReleaseVersion: "24H2"}}}}, "windowsUpdate.featureUpdates", "Windows 10 or"},
		{"pin version", LevelOrganization, PolicyLayer{WindowsUpdate: &LayerWindowsUpdate{FeatureUpdates: &GroupSetting[FeatureUpdates]{Managed: true,
			Value: &FeatureUpdates{TargetProductVersion: "Windows 11", TargetReleaseVersion: "2024"}}}}, "windowsUpdate.featureUpdates", "24H2"},
		{"feature defer", LevelOrganization, PolicyLayer{WindowsUpdate: &LayerWindowsUpdate{FeatureUpdates: &GroupSetting[FeatureUpdates]{Managed: true,
			Value: &FeatureUpdates{DeferDays: ptr(400)}}}}, "windowsUpdate.featureUpdates", "0 to 365"},
		{"quality defer", LevelOrganization, PolicyLayer{WindowsUpdate: &LayerWindowsUpdate{QualityUpdates: &GroupSetting[QualityUpdates]{Managed: true,
			Value: &QualityUpdates{DeferDays: ptr(31)}}}}, "windowsUpdate.qualityUpdates", "0 to 30"},
		{"active hours half", LevelOrganization, PolicyLayer{WindowsUpdate: &LayerWindowsUpdate{RestartBehavior: &GroupSetting[RestartBehavior]{Managed: true,
			Value: &RestartBehavior{ActiveHoursStart: ptr(8)}}}}, "windowsUpdate.restartBehavior", "both the start"},
		{"active hours range", LevelOrganization, PolicyLayer{WindowsUpdate: &LayerWindowsUpdate{RestartBehavior: &GroupSetting[RestartBehavior]{Managed: true,
			Value: &RestartBehavior{ActiveHoursStart: ptr(8), ActiveHoursEnd: ptr(24)}}}}, "windowsUpdate.restartBehavior", "0 to 23"},
		{"active hours span", LevelOrganization, PolicyLayer{WindowsUpdate: &LayerWindowsUpdate{RestartBehavior: &GroupSetting[RestartBehavior]{Managed: true,
			Value: &RestartBehavior{ActiveHoursStart: ptr(6), ActiveHoursEnd: ptr(1)}}}}, "windowsUpdate.restartBehavior", "1 to 18"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := fieldErrs(t, normalizePolicy(&tc.p, tc.level, inherited))
			if !strings.Contains(got[tc.field], tc.text) {
				t.Fatalf("%s: %q, want %q (all: %v)", tc.field, got[tc.field], tc.text, got)
			}
		})
	}
}

func TestNormalizePolicyCleansUp(t *testing.T) {
	inherited, _ := resolvePolicy(nil)
	p := PolicyLayer{AllowedCategories: []string{"security", "Security", "driver"}, MaintenanceDays: []int{5, 1, 5}, AutoInstallEnabled: ptr(true),
		ExcludedKbs:     []string{" kb123 ", "KB123", "5044284"},
		RestartSchedule: &RestartSchedule{Enabled: true, Days: []int{3, 1, 3}},
		WindowsUpdate: &LayerWindowsUpdate{AutomaticUpdates: &GroupSetting[AutomaticUpdates]{Managed: false, Value: &AutomaticUpdates{Mode: "Disabled"}},
			FeatureUpdates: &GroupSetting[FeatureUpdates]{Managed: true, Value: &FeatureUpdates{TargetProductVersion: " Windows 11 ", TargetReleaseVersion: "24h2"}},
			QualityUpdates: &GroupSetting[QualityUpdates]{Managed: false}, RestartBehavior: &GroupSetting[RestartBehavior]{Managed: false}},
		ApplicationUpdates: &ApplicationUpdates{Enabled: true, ApprovedApps: []string{" Mozilla.Firefox", "mozilla.firefox", "7zip.7zip"}}}
	if err := normalizePolicy(&p, LevelOrganization, inherited); err != nil {
		t.Fatal(err)
	}
	switch {
	case !slices.Equal(p.AllowedCategories, []string{"Security", "Driver"}):
		t.Errorf("categories: %v", p.AllowedCategories)
	case !slices.Equal(p.MaintenanceDays, []int{1, 5}) || *p.MaintenanceStart != "02:00" || *p.MaintenanceDurationMinutes != 180:
		t.Errorf("window: %v", p.MaintenanceDays)
	case !slices.Equal(p.ExcludedKbs, []string{"KB123", "KB5044284"}):
		t.Errorf("KBs: %v", p.ExcludedKbs)
	case !slices.Equal(p.RestartSchedule.Days, []int{1, 3}) || p.RestartSchedule.Time != "03:00" || p.RestartSchedule.Mode != "PromptWithDeadline" ||
		p.RestartSchedule.Condition != "OnlyIfPending" || p.RestartSchedule.DeadlineMinutes != 240 || p.RestartSchedule.ExpiryMinutes != 120:
		t.Errorf("restart schedule: %+v", p.RestartSchedule)
	case p.WindowsUpdate.AutomaticUpdates.Value != nil:
		t.Error("a group left alone keeps no settings")
	case p.WindowsUpdate.FeatureUpdates.Value.TargetProductVersion != "Windows 11" || p.WindowsUpdate.FeatureUpdates.Value.TargetReleaseVersion != "24H2":
		t.Errorf("pin: %+v", p.WindowsUpdate.FeatureUpdates.Value)
	case !slices.Equal(p.ApplicationUpdates.ApprovedApps, []string{"Mozilla.Firefox", "7zip.7zip"}):
		t.Errorf("apps: %v", p.ApplicationUpdates.ApprovedApps)
	}

	// A tag that turns automatic installs on leaves each device's window to
	// its organization or site; a level that touches neither is not held to
	// what it inherits.
	for _, tc := range []struct {
		level string
		p     PolicyLayer
		inh   PolicyLayer
	}{
		{LevelTag, PolicyLayer{AutoInstallEnabled: ptr(true)}, inherited},
		{LevelSite, PolicyLayer{ScanIntervalMinutes: ptr(60)}, PolicyLayer{AutoInstallEnabled: ptr(true), MaintenanceDays: []int{}}},
		{LevelDevice, PolicyLayer{AutoInstallEnabled: ptr(true)}, PolicyLayer{MaintenanceDays: []int{2}}},
		{LevelOrganization, PolicyLayer{RestartSchedule: &RestartSchedule{Enabled: false, Days: []int{}}}, inherited},
		{LevelOrganization, PolicyLayer{ApplicationUpdates: &ApplicationUpdates{Enabled: true}}, inherited},
	} {
		if err := normalizePolicy(&tc.p, tc.level, tc.inh); err != nil {
			t.Errorf("%s %+v: %v", tc.level, tc.p, err)
		}
	}
	if tooMany := (PolicyLayer{ApplicationUpdates: &ApplicationUpdates{}}); true {
		for i := range 101 {
			tooMany.ApplicationUpdates.ApprovedApps = append(tooMany.ApplicationUpdates.ApprovedApps, "Vendor.App"+strings.Repeat("x", i))
		}
		if !strings.Contains(fieldErrs(t, normalizePolicy(&tooMany, LevelOrganization, inherited))["applicationUpdates"], "at most 100") {
			t.Error("101 applications")
		}
	}
}

func TestChangedPolicyFields(t *testing.T) {
	before := PolicyLayer{ScanIntervalMinutes: ptr(60), ExcludedKbs: nil, MaintenanceDays: []int{1}}
	after := PolicyLayer{ScanIntervalMinutes: ptr(60), ExcludedKbs: []string{}, MaintenanceDays: []int{1, 2}, AutoInstallEnabled: ptr(true)}
	if got := changedPolicyFields(before, after); !slices.Equal(got, []string{"autoInstallEnabled", "maintenanceDays"}) {
		t.Fatalf("changed: %v", got)
	}
	if got := changedPolicyFields(after, PolicyLayer{ScanIntervalMinutes: ptr(60), MaintenanceDays: []int{1, 2}, AutoInstallEnabled: ptr(true),
		ExcludedKbs: []string{"KB1"}}); !slices.Equal(got, []string{"excludedKbs"}) {
		t.Fatalf("changed KBs: %v", got)
	}
}

func TestParsePolicyLevel(t *testing.T) {
	for _, l := range []string{"default", "organization", "site", "device", "tag"} {
		if got, err := ParsePolicyLevel(l); err != nil || got != l {
			t.Errorf("%s: %s, %v", l, got, err)
		}
	}
	if _, err := ParsePolicyLevel("group"); fieldErrs(t, err)["level"] == "" {
		t.Error("group is no level")
	}
}

func TestNormalizeTag(t *testing.T) {
	in := TagInput{Name: "  Ring 1 ", Color: "blue", Priority: 10, Description: ptr("   ")}
	if err := normalizeTag(&in); err != nil || in.Name != "Ring 1" || in.Description != nil {
		t.Fatalf("%+v, %v", in, err)
	}
	in.Description = ptr(" Pilot machines ")
	if err := normalizeTag(&in); err != nil || *in.Description != "Pilot machines" {
		t.Fatalf("%+v, %v", in, err)
	}
	for _, tc := range []struct {
		in    TagInput
		field string
	}{
		{TagInput{Name: "", Color: "blue"}, "name"},
		{TagInput{Name: strings.Repeat("x", 41), Color: "blue"}, "name"},
		{TagInput{Name: "a\tb", Color: "blue"}, "name"},
		{TagInput{Name: "ok", Color: "orange"}, "color"},
		{TagInput{Name: "ok", Color: "red", Priority: 1001}, "priority"},
		{TagInput{Name: "ok", Color: "red", Priority: -1}, "priority"},
		{TagInput{Name: "ok", Color: "red", Description: ptr(strings.Repeat("d", 501))}, "description"},
	} {
		if fieldErrs(t, normalizeTag(&tc.in))[tc.field] == "" {
			t.Errorf("%+v: want an error on %s", tc.in, tc.field)
		}
	}
}
