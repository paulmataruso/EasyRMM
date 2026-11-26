package notify

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRuleMatches(t *testing.T) {
	org, other, site, site2, group := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	base := Rule{Enabled: true, Source: SourceAlerts,
		Organizations: ListFilter{Mode: ModeAny}, Sites: ListFilter{Mode: ModeAny}, Groups: ListFilter{Mode: ModeAny},
		DeviceKinds: ValueFilter{Mode: ModeAny}, Severities: ValueFilter{Mode: ModeAny}, Conditions: ValueFilter{Mode: ModeAny}, Checks: ValueFilter{Mode: ModeAny}}
	subj := Subject{Source: SourceAlerts, Org: org, Site: site, Group: &group, Kind: "server", Severity: "critical", Condition: "offline"}
	with := func(f func(r *Rule)) Rule {
		r := base
		f(&r)
		return r
	}
	for name, tc := range map[string]struct {
		rule Rule
		s    Subject
		want bool
	}{
		"any matches":                     {base, subj, true},
		"disabled":                        {with(func(r *Rule) { r.Enabled = false }), subj, false},
		"a notice rule is not alerts":     {with(func(r *Rule) { r.Source = SourceNotices }), subj, false},
		"its own organization":            {with(func(r *Rule) { r.OrganizationID = &org }), subj, true},
		"never another's devices":         {with(func(r *Rule) { r.OrganizationID = &other }), subj, false},
		"organization in list":            {with(func(r *Rule) { r.Organizations = ListFilter{ModeList, []uuid.UUID{org}} }), subj, true},
		"organization not in list":        {with(func(r *Rule) { r.Organizations = ListFilter{ModeList, []uuid.UUID{other}} }), subj, false},
		"an emptied list matches nothing": {with(func(r *Rule) { r.Sites = ListFilter{ModeList, nil} }), subj, false},
		"site in list":                    {with(func(r *Rule) { r.Sites = ListFilter{ModeList, []uuid.UUID{site, site2}} }), subj, true},
		"site not in list":                {with(func(r *Rule) { r.Sites = ListFilter{ModeList, []uuid.UUID{site2}} }), subj, false},
		"group in list":                   {with(func(r *Rule) { r.Groups = ListFilter{ModeList, []uuid.UUID{group}} }), subj, true},
		"a device in no group":            {with(func(r *Rule) { r.Groups = ListFilter{ModeList, []uuid.UUID{group}} }), Subject{Source: SourceAlerts, Org: org, Site: site}, false},
		"servers":                         {with(func(r *Rule) { r.DeviceKinds = ValueFilter{ModeList, []string{"server"}} }), subj, true},
		"workstations":                    {with(func(r *Rule) { r.DeviceKinds = ValueFilter{ModeList, []string{"workstation"}} }), subj, false},
		"an unknown kind matches only any": {with(func(r *Rule) { r.DeviceKinds = ValueFilter{ModeList, []string{"server", "workstation"}} }),
			Subject{Source: SourceAlerts, Org: org, Site: site, Severity: "warning", Condition: "cpu"}, false},
		"severity":  {with(func(r *Rule) { r.Severities = ValueFilter{ModeList, []string{"warning"}} }), subj, false},
		"condition": {with(func(r *Rule) { r.Conditions = ValueFilter{ModeList, []string{"cpu", "offline"}} }), subj, true},
		"a disk-health check": {with(func(r *Rule) { r.Checks = ValueFilter{ModeList, []string{"wear"}} }),
			Subject{Source: SourceAlerts, Org: org, Site: site, Condition: "disk_health", Check: "failing"}, false},
		"a check of the right kind": {with(func(r *Rule) { r.Checks = ValueFilter{ModeList, []string{"wear"}} }),
			Subject{Source: SourceAlerts, Org: org, Site: site, Condition: "disk_health", Check: "wear"}, true},
		"checks do not filter other conditions": {with(func(r *Rule) { r.Checks = ValueFilter{ModeList, []string{"wear"}} }), subj, true},
	} {
		if got := tc.rule.Matches(tc.s); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}

func TestDeviceKind(t *testing.T) {
	s, w := "server", "workstation"
	bad := "toaster"
	for name, tc := range map[string]struct {
		set, reported *string
		os, platform  string
		want          string
	}{
		"a person's kind wins":       {&w, &s, "Microsoft Windows Server 2025", "windows", "workstation"},
		"the agent's role":           {nil, &w, "Microsoft Windows Server 2025", "windows", "workstation"},
		"an unknown role is ignored": {&bad, nil, "Windows 11 Pro", "windows", "workstation"},
		"MeshCentral's description":  {nil, nil, "Microsoft Windows Server 2022 Datacenter", "windows", "server"},
		"a Windows workstation":      {nil, nil, "Windows 11 Pro", "windows", "workstation"},
		"Linux is a server":          {nil, nil, "Ubuntu 24.04", "linux", "server"},
		"macOS is a workstation":     {nil, nil, "macOS 15", "macos", "workstation"},
		"a server named elsewhere":   {nil, nil, "windows server 2019", "other", "server"},
		"unknown":                    {nil, nil, "something", "other", ""},
	} {
		if got := DeviceKind(tc.set, tc.reported, tc.os, tc.platform); got != tc.want {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
	}
}

func TestCleanAndDefang(t *testing.T) {
	long := strings.Repeat("a", 80)
	for name, tc := range map[string]struct {
		in   string
		n    int
		want string
	}{
		"plain":                     {"SRV01", 64, "SRV01"},
		"clipped":                   {long, 64, strings.Repeat("a", 63) + "…"},
		"control and bidi":          {"a\u202eb\u0000c\u2028d\u2029e\u200bf", 64, "abcdef"},
		"NFKC":                      {"ｓｅｒｖｅｒ", 64, "server"},
		"the ideographic full stop": {"evil。example", 64, "evil.example"},
		"the fullwidth full stop":   {"evil．example", 64, "evil.example"},
		"halfwidth ideographic":     {"evil｡example", 64, "evil.example"},
	} {
		if got := Clean(tc.in, tc.n); got != tc.want {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
	}
	for in, want := range map[string]string{
		"SRV01":                "SRV01",
		"Main office":          "Main office",
		"https://evil.example": "https[://]evil[.]example",
		"www.evil.example":     "www[.]evil[.]example",
		"a@evil.example":       "a[@]evil[.]example",
		"evil.example":         "evil[.]example",
		"build 10.2":           "build 10.2",
		"<!channel>":           "<!channel>",
	} {
		if got := Defang(in); got != want {
			t.Errorf("Defang(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWallInstantAcrossDaylightSaving(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip("no tzdata")
	}
	// 2026-03-08 02:30 does not exist: the window begins when the gap ends, 03:00 EDT.
	gap := wallInstant(ny, 2026, time.March, 8, 2, 30)
	if want := time.Date(2026, time.March, 8, 7, 0, 0, 0, time.UTC); !gap.Equal(want) {
		t.Errorf("a start in the skipped hour is %v, want %v", gap, want)
	}
	// 2026-11-01 01:30 happens twice: the first, 01:30 EDT.
	rep := wallInstant(ny, 2026, time.November, 1, 1, 30)
	if want := time.Date(2026, time.November, 1, 5, 30, 0, 0, time.UTC); !rep.Equal(want) {
		t.Errorf("a start in the repeated hour is %v, want %v", rep, want)
	}
	plain := wallInstant(ny, 2026, time.June, 1, 22, 0)
	if want := time.Date(2026, time.June, 2, 2, 0, 0, 0, time.UTC); !plain.Equal(want) {
		t.Errorf("an ordinary start is %v, want %v", plain, want)
	}
	syd, err := time.LoadLocation("Australia/Sydney")
	if err == nil {
		// 2026-10-04 02:30 is skipped in Sydney; the gap ends at 03:00 AEDT (16:00 UTC the day before).
		g := wallInstant(syd, 2026, time.October, 4, 2, 30)
		if want := time.Date(2026, time.October, 3, 16, 0, 0, 0, time.UTC); !g.Equal(want) {
			t.Errorf("southern gap %v, want %v", g, want)
		}
	}
}

func TestWindowActive(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip("no tzdata")
	}
	// Friday 22:00 for 8 hours, across midnight into Saturday: it belongs to Friday.
	w := Window{Kind: "weekly", Days: []int{5}, Start: "22:00", LengthMinutes: 8 * 60, Enabled: true}
	at := func(y int, mo time.Month, d, h, mi int) time.Time { return time.Date(y, mo, d, h, mi, 0, 0, ny) }
	for name, tc := range map[string]struct {
		at   time.Time
		want bool
	}{
		"Friday 21:59":   {at(2026, time.November, 27, 21, 59), false},
		"Friday 22:00":   {at(2026, time.November, 27, 22, 0), true},
		"Saturday 03:00": {at(2026, time.November, 28, 3, 0), true},
		"Saturday 05:59": {at(2026, time.November, 28, 5, 59), true},
		"Saturday 06:00": {at(2026, time.November, 28, 6, 0), false},
		"Saturday 22:30": {at(2026, time.November, 28, 22, 30), false},
		"Sunday 01:00":   {at(2026, time.November, 29, 1, 0), false},
	} {
		if got := w.ActiveAt(ny, tc.at); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
	// Lengths are elapsed time: Saturday 2026-03-07 22:00 for 8 hours ends at 07:00 EDT, not 06:00.
	dst := Window{Kind: "weekly", Days: []int{6}, Start: "22:00", LengthMinutes: 8 * 60, Enabled: true}
	if !dst.ActiveAt(ny, at(2026, time.March, 8, 6, 30)) || dst.ActiveAt(ny, at(2026, time.March, 8, 7, 0)) {
		t.Error("a window's length is elapsed time across the spring change")
	}
	off := w
	off.Enabled = false
	if off.ActiveAt(ny, at(2026, time.November, 28, 3, 0)) {
		t.Error("a disabled window holds nothing")
	}
	once := Window{Kind: "once", StartsAt: "2026-12-01T09:00", LengthMinutes: 90, Enabled: true}
	if !once.ActiveAt(ny, at(2026, time.December, 1, 10, 0)) || once.ActiveAt(ny, at(2026, time.December, 1, 10, 30)) || once.ActiveAt(ny, at(2026, time.December, 1, 8, 59)) {
		t.Error("a one-off window")
	}
	if (&Window{Kind: "weekly", Start: "junk", Days: []int{1}, Enabled: true}).ActiveAt(ny, time.Now()) || (&Window{Kind: "once", StartsAt: "junk", Enabled: true}).ActiveAt(ny, time.Now()) {
		t.Error("a window nobody can read holds nothing")
	}
}

func TestDigestMergeLeavesOutWhatWasOpenedAndResolved(t *testing.T) {
	a, b := AlertItem{ID: uuid.New(), Name: "Device offline", Device: "SRV01", Site: "Main", Severity: "critical", OpenedAt: time.Now()}, AlertItem{ID: uuid.New(), Name: "Disk", Severity: "warning"}
	d := &Digest{}
	d.merge(outEvent{op: opOpened, alert: &a})
	d.merge(outEvent{op: opOpened, alert: &b})
	d.merge(outEvent{op: opResolved, alert: &a})
	if len(d.New) != 1 || d.New[0].ID != b.ID || len(d.Resolved) != 0 {
		t.Fatalf("an alert opened and resolved before the digest went is left out: %+v", d)
	}
	d.merge(outEvent{op: opReminder, alert: &b})
	if len(d.Open) != 0 {
		t.Fatal("a new alert is not also still open")
	}
	d.merge(outEvent{op: opResolved, alert: &AlertItem{ID: uuid.New(), Name: "Told before"}})
	if len(d.Resolved) != 1 {
		t.Fatal("what was told before is told as resolved")
	}
	c := AlertItem{ID: uuid.New(), Name: "Memory"}
	d.merge(outEvent{op: opReminder, alert: &c})
	d.merge(outEvent{op: opReminder, alert: &c})
	if len(d.Open) != 1 {
		t.Fatal("a reminder is listed once")
	}
	o := OutageItem{ID: uuid.New(), Site: "Main", Devices: 3, StartedAt: time.Now()}
	d.merge(outEvent{op: opDown, outage: &o})
	d.merge(outEvent{op: opUp, outage: &o})
	if len(d.Down) != 0 || len(d.Up) != 0 {
		t.Fatalf("an outage that began and ended unsent is left out: %+v", d)
	}
	o2 := OutageItem{ID: uuid.New(), Site: "Other", Devices: 4}
	d.merge(outEvent{op: opUp, outage: &o2})
	n := NoticeBody{ID: uuid.New(), Title: "Channel failing"}
	d.merge(outEvent{op: opNoticeOpened, notice: &n})
	d.merge(outEvent{op: opNoticeResolved, notice: &n})
	d.merge(outEvent{op: opNoticeResolved, notice: &NoticeBody{ID: uuid.New(), Title: "Other"}})
	if len(d.Up) != 1 || len(d.Notices) != 1 || !strings.HasPrefix(d.Notices[0].Title, "Resolved: ") {
		t.Fatalf("%+v", d)
	}
	if d.empty() {
		t.Fatal("not empty")
	}
	l := d.letter("https://rmm.example.com")
	if l.Link == nil || !strings.HasSuffix(l.Link.URL, "/alerts") || !strings.Contains(l.Subject, "new") {
		t.Fatalf("%+v", l)
	}
	if (&Digest{}).letter("").Link != nil || (&Digest{}).subjectLine() != "EasyRMM alerts" {
		t.Fatal("an empty digest")
	}
}

func TestEmailListsAtMostTwentyFiveAlerts(t *testing.T) {
	d := &Digest{}
	for i := range 30 {
		d.New = append(d.New, AlertItem{ID: uuid.New(), Name: "Offline", Device: "SRV" + string(rune('A'+i%26)), Site: "Main", Severity: "warning", OpenedAt: time.Now()})
	}
	l := d.letter("")
	lines := 0
	more := false
	for _, p := range l.Before {
		if strings.HasPrefix(p, "Warning:") {
			lines++
		}
		if strings.Contains(p, "and 5 more") {
			more = true
		}
	}
	if lines != EmailAlerts || !more {
		t.Fatalf("%d lines, more=%v", lines, more)
	}
}

func TestEventTexts(t *testing.T) {
	a := AlertItem{Name: "Device offline", Device: "SRV01", Site: "Main", Severity: "critical"}
	o := OutageItem{Site: "Main", Devices: 5, Back: 4}
	n := NoticeBody{Title: "Title", Detail: "Detail"}
	for _, ev := range []outEvent{{op: opOpened, alert: &a}, {op: opResolved, alert: &a}, {op: opDown, outage: &o}, {op: opUp, outage: &o}, {op: opNoticeOpened, notice: &n}, {name: "x"}} {
		if eventSubject(ev) == "" || eventSummary(ev) == "" {
			t.Errorf("%+v", ev)
		}
	}
}

func TestIsTransient(t *testing.T) {
	if isTransient(nil) || isTransient(errString("nope")) {
		t.Fatal("not transient")
	}
}

type errString string

func (e errString) Error() string { return string(e) }
