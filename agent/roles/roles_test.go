package roles

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

func svcs(running []string, stopped ...string) map[string]Service {
	m := map[string]Service{}
	for _, n := range running {
		m[n] = Running
	}
	for _, n := range stopped {
		m[n] = Stopped
	}
	return m
}

func names(rs []agentproto.Role) []string {
	out := []string{}
	for _, r := range rs {
		out = append(out, r.Name+":"+r.State)
	}
	return out
}

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name string
		in   Inputs
		want []string
	}{
		{"domain controller", Inputs{ProductType: ProductController, Services: svcs([]string{"NTDS", "DNS", "LanmanServer"}, "wbengine"), Shares: 2},
			[]string{"ad_ds:present", "dns:present", "file_server:present", "windows_backup:present"}},
		{"former domain controller: NTDS runs, product type is a server", Inputs{ProductType: ProductServer, Services: svcs([]string{"NTDS"})},
			[]string{}},
		{"ad_ds needs the service running", Inputs{ProductType: ProductController, Services: svcs(nil, "NTDS")}, []string{}},
		{"CA with configuration", Inputs{ProductType: ProductServer, Services: svcs([]string{"CertSvc"}), CAConfigured: true}, []string{"ad_cs:present"}},
		{"CA installed but not configured", Inputs{ProductType: ProductServer, Services: svcs([]string{"CertSvc"})}, []string{}},
		{"DNS on a desktop is not reported", Inputs{ProductType: ProductClient, Services: svcs([]string{"DNS"})}, []string{"windows_backup:unconfigured"}},
		{"DHCP configured", Inputs{ProductType: ProductServer, Services: svcs([]string{"DHCPServer"}), DHCPParameters: true}, []string{"dhcp:present"}},
		{"DHCP installed, unconfigured", Inputs{ProductType: ProductServer, Services: svcs([]string{"DHCPServer"})}, []string{"dhcp:unconfigured"}},
		{"file server without a share", Inputs{ProductType: ProductServer, Services: svcs([]string{"LanmanServer"})}, []string{}},
		{"desktop with a share is not a file server", Inputs{ProductType: ProductClient, Services: svcs([]string{"LanmanServer"}), Shares: 1}, []string{"windows_backup:unconfigured"}},
		{"print spooler without a shared printer", Inputs{ProductType: ProductServer, Services: svcs([]string{"Spooler"})}, []string{}},
		{"print server", Inputs{ProductType: ProductServer, Services: svcs([]string{"Spooler"}), PrintShared: true}, []string{"print_server:present"}},
		{"print spooler on a desktop", Inputs{ProductType: ProductClient, Services: svcs([]string{"Spooler"}), PrintShared: true}, []string{"windows_backup:unconfigured"}},
		{"backup on a server needs the product type, not only the service", Inputs{ProductType: ProductServer, Services: svcs(nil, "wbengine")}, []string{"windows_backup:present"}},
		{"desktop backup with File History", Inputs{ProductType: ProductClient, Services: svcs([]string{"fhsvc"}, "wbengine")}, []string{"windows_backup:present"}},
		{"defender normal", Inputs{ProductType: ProductServer, Services: svcs([]string{"WinDefend"}), Defender: Defender{Read: true, RunningMode: "Normal", Version: "4.18"}},
			[]string{"defender:present"}},
		{"defender passive", Inputs{ProductType: ProductServer, Services: svcs([]string{"WinDefend"}), Defender: Defender{Read: true, RunningMode: "Passive"}},
			[]string{"defender:passive"}},
		{"defender query failed", Inputs{ProductType: ProductServer, Services: svcs([]string{"WinDefend"})}, []string{"defender:unknown"}},
		{"defender absent", Inputs{ProductType: ProductServer, Services: svcs(nil)}, []string{}},
		{"unknown product type reports no server roles", Inputs{ProductType: "", Services: svcs([]string{"DNS", "NTDS"})}, []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Evaluate(tt.in)
			if got == nil {
				t.Fatal("Evaluate returned nil")
			}
			if !slices.Equal(names(got), tt.want) {
				t.Errorf("got %v, want %v", names(got), tt.want)
			}
		})
	}
}

func TestEvaluateCarriesDefenderVersion(t *testing.T) {
	got := Evaluate(Inputs{ProductType: ProductServer, Services: svcs([]string{"WinDefend"}), Defender: Defender{Read: true, RunningMode: "Normal", Version: "4.18.1"}})
	if len(got) != 1 || got[0].Version != "4.18.1" {
		t.Fatalf("got %+v", got)
	}
}

func TestParseDefender(t *testing.T) {
	d, err := ParseDefender([]byte("\xef\xbb\xbf{\"AMRunningMode\":\"Passive\",\"AMProductVersion\":\"4.18.2\"}\r\n"))
	if err != nil || !d.Read || d.RunningMode != "Passive" || d.Version != "4.18.2" {
		t.Fatalf("got %+v, %v", d, err)
	}
	for _, bad := range []string{"", "not json", `{}`} {
		if _, err := ParseDefender([]byte(bad)); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
}

func TestScanner(t *testing.T) {
	now := time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC)
	reads := 0
	fail := false
	s := &Scanner{Now: func() time.Time { return now }, Read: func(context.Context) (Inputs, error) {
		reads++
		if fail {
			return Inputs{}, errors.New("boom")
		}
		return Inputs{ProductType: ProductServer, Services: svcs([]string{"DNS"})}, nil
	}}
	ctx := context.Background()
	if got := s.Roles(ctx); len(got) != 1 || reads != 1 {
		t.Fatalf("first: %v reads=%d", got, reads)
	}
	now = now.Add(5*time.Hour + 59*time.Minute)
	s.Roles(ctx)
	if reads != 1 {
		t.Fatalf("read again inside the interval: %d", reads)
	}
	now = now.Add(2 * time.Minute)
	s.Roles(ctx)
	if reads != 2 {
		t.Fatalf("did not read after 6 hours: %d", reads)
	}
	s.Rescan()
	s.Roles(ctx)
	if reads != 3 {
		t.Fatalf("did not rescan on request: %d", reads)
	}
	// A failed read keeps the last result and waits for the interval.
	fail = true
	s.Rescan()
	if got := s.Roles(ctx); len(got) != 1 || reads != 4 {
		t.Fatalf("after a failure: %v reads=%d", got, reads)
	}
	s.Roles(ctx)
	if reads != 4 {
		t.Fatalf("retried a failed read at once: %d", reads)
	}
}

func TestScannerNeverReadSendsNothing(t *testing.T) {
	if got := (&Scanner{}).Roles(context.Background()); got != nil {
		t.Fatalf("got %v", got)
	}
	s := &Scanner{Read: func(context.Context) (Inputs, error) { return Inputs{}, errors.New("x") }}
	if got := s.Roles(context.Background()); got != nil {
		t.Fatalf("a first failure must report no roles, got %v", got)
	}
}
