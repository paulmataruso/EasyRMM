package reports

import (
	"bytes"
	"encoding/csv"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
)

func TestWriteCSV(t *testing.T) {
	at := time.Date(2026, 11, 16, 13, 53, 7, 0, time.FixedZone("CET", 3600))
	rep := &Report{
		Name: "devices",
		Columns: []Column{
			{"device", "Device", TypeText}, {"online", "Online", TypeBool}, {"seen", "Last seen", TypeTime},
			{"cpu", "Processor", TypePercent}, {"cores", "Cores", TypeNumber}, {"note", "Note", TypeText},
		},
		Rows: [][]any{
			{"WEB-01", true, at, 12.5, 8, "plain, with a comma"},
			{"=HYPERLINK(\"http://example.com\")", false, nil, nil, int64(3), "-2+3"},
			{"@SUM(A1)", nil, nil, 0.0, nil, "\ttab"},
			{"Ünïcode \"quoted\"", true}, // a short row is padded
		},
		GeneratedAt: at,
	}
	var buf bytes.Buffer
	if err := WriteCSV(&buf, rep); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte("\xef\xbb\xbf")) {
		t.Error("no byte order mark")
	}
	records, err := csv.NewReader(bytes.NewReader(buf.Bytes()[3:])).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"Device", "Online", "Last seen (UTC)", "Processor (%)", "Cores", "Note"},
		{"WEB-01", "Yes", "2026-11-16 12:53:07", "12.5", "8", "plain, with a comma"},
		{"'=HYPERLINK(\"http://example.com\")", "No", "", "", "3", "'-2+3"},
		{"'@SUM(A1)", "", "", "0", "", "'\ttab"},
		{"Ünïcode \"quoted\"", "Yes", "", "", "", ""},
	}
	if len(records) != len(want) {
		t.Fatalf("records %q", records)
	}
	for i := range want {
		if !slices.Equal(records[i], want[i]) {
			t.Errorf("row %d: %q, want %q", i, records[i], want[i])
		}
	}
	if FileName(rep) != "easyrmm-devices-2026-11-16.csv" {
		t.Errorf("file name %s", FileName(rep))
	}
	if cell(struct{}{}) != "" || cell(int64(-4)) != "-4" {
		t.Error("odd cells")
	}
}

func TestQueryChecks(t *testing.T) {
	q := Query{}
	if err := q.check(); err != nil || q.Days != DefaultDays {
		t.Errorf("defaults: %v, %d days", err, q.Days)
	}
	for field, bad := range map[string]Query{
		"platform":    {Platform: "macos"},
		"q":           {Search: strings.Repeat("x", 201)},
		"days":        {Days: 366},
		"offlineDays": {OfflineDays: -1},
		"diskPercent": {DiskPercent: 101},
		"severity":    {Severity: "info"},
	} {
		err := bad.check()
		e, ok := apperr.As(err)
		if !ok || e.Fields[field] == "" {
			t.Errorf("%s: %v", field, err)
		}
	}
}

func TestHelpers(t *testing.T) {
	got := addresses([]agentproto.Interface{
		{Name: "lo", Addresses: []string{"127.0.0.1/8", "::1/128"}},
		{Name: "eth0", Addresses: []string{"192.0.2.10/24", "fe80::1/64", "2001:db8::10/64", "not an address"}},
		{Name: "eth1", Addresses: []string{"192.0.2.10/24", "0.0.0.0/0"}},
	})
	if !slices.Equal(got, []string{"192.0.2.10", "2001:db8::10"}) {
		t.Errorf("addresses %q", got)
	}
	if n := diskBytes([]agentproto.Disk{{SizeBytes: 100}, {SizeBytes: 50, Removable: true}, {SizeBytes: 25}}); n != 125 {
		t.Errorf("disk bytes %d", n)
	}
	mount, used, free, ok := fullest([]agentproto.Filesystem{
		{Mount: "/", TotalBytes: 100, UsedBytes: 50},
		{Mount: "/var", TotalBytes: 200, UsedBytes: 180},
		{Mount: "/empty", TotalBytes: 0},
	})
	if !ok || mount != "/var" || used != 90 || free != 20 {
		t.Errorf("fullest %s %v %v %v", mount, used, free, ok)
	}
	if _, _, _, ok := fullest(nil); ok {
		t.Error("a fullest filesystem of none")
	}
	if likePattern("  50%_off\\ ") != `%50\%\_off\\%` || likePattern(" ") != "" {
		t.Errorf("like %q", likePattern("  50%_off\\ "))
	}
	if platformName("windows") != "Windows" || platformName("beos") != "beos" {
		t.Error("platform names")
	}
	if round1(12.345) != 12.3 || timeOrNil(nil) != nil {
		t.Error("round1 or timeOrNil")
	}
	if !slices.Equal(Names(), []string{"devices", "software", "health", "alerts", "patch-compliance", "patch-installations"}) {
		t.Error("names")
	}
	for _, n := range Names() {
		if _, ok := definitions[n]; !ok {
			t.Errorf("no definition for %s", n)
		}
	}
}
