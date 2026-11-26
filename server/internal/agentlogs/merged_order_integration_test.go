//go:build integration

package agentlogs_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/agentlogs"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// The Logs tab reads every source as one list in time order, newest first,
// whatever order the batches arrived in (ADR-0069, amended 2026-11-26).

func messages(items []agentlogs.Record) []string {
	var m []string
	for _, r := range items {
		m = append(m, r.Message)
	}
	return m
}

// interleaved stores three sources in batches that arrive out of time order:
// the EasyPatch agent's batch comes late and holds older records, and two
// records share a time.
func interleaved(f *fixture) time.Time {
	t0 := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	rec := func(seq int64, src string, s int, msg string) agentproto.LogRecord {
		return agentproto.LogRecord{Seq: seq, Time: at(s), Source: src, Level: "info", Message: msg}
	}
	f.ingest(f.dev, agentproto.LogBatch{Records: []agentproto.LogRecord{rec(1, "agent", 1, "agent 1"), rec(2, "agent", 6, "agent 6"), rec(3, "meshagent", 4, "mesh 4")}})
	// Late, with older times.
	f.ingest(f.dev, agentproto.LogBatch{Records: []agentproto.LogRecord{rec(4, "easypatch", 2, "patch 2"), rec(5, "easypatch", 5, "patch 5"), rec(6, "easypatch", 4, "patch 4 same time as mesh")}})
	f.ingest(f.dev, agentproto.LogBatch{Records: []agentproto.LogRecord{rec(7, "meshagent", 3, "mesh 3"), rec(8, "agent", 7, "agent 7")}})
	return t0
}

var wantNewestFirst = []string{"agent 7", "agent 6", "patch 5", "patch 4 same time as mesh", "mesh 4", "mesh 3", "patch 2", "agent 1"}

func TestReadIsStrictlyTimeOrderedAcrossSourcesNewestFirstWithAStableTieBreak(t *testing.T) {
	f := newFixture(t, 14)
	interleaved(f)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	for i := 0; i < 3; i++ {
		p, err := f.svc.Read(f.ctx, tech, f.dev, agentlogs.Query{Limit: 100}, false)
		if err != nil {
			t.Fatal(err)
		}
		// Equal times: the one stored later (higher id) first, every time.
		if got := messages(p.Items); strings.Join(got, "|") != strings.Join(wantNewestFirst, "|") {
			t.Fatalf("read %d = %v", i, got)
		}
	}
	// A filter keeps the order.
	p, err := f.svc.Read(f.ctx, tech, f.dev, agentlogs.Query{Sources: []string{"easypatch", "meshagent"}, Limit: 100}, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(messages(p.Items), "|"); got != "patch 5|patch 4 same time as mesh|mesh 4|mesh 3|patch 2" {
		t.Errorf("filtered = %s", got)
	}
}

func TestPagingToOlderRecordsFollowsTheMergedOrderAndMissesNone(t *testing.T) {
	f := newFixture(t, 14)
	interleaved(f)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	var all []string
	q := agentlogs.Query{Limit: 3}
	for pages := 0; pages < 10; pages++ {
		p, err := f.svc.Read(f.ctx, tech, f.dev, q, false)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, messages(p.Items)...)
		if !p.More {
			break
		}
		q.Before = p.Items[len(p.Items)-1].ID
	}
	if strings.Join(all, "|") != strings.Join(wantNewestFirst, "|") {
		t.Errorf("pages = %v", all)
	}
}

func TestTheLiveTailReturnsWhatWasStoredAfterTheCursorEvenWhenItIsOlder(t *testing.T) {
	f := newFixture(t, 14)
	t0 := interleaved(f)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	p, _ := f.svc.Read(f.ctx, tech, f.dev, agentlogs.Query{Limit: 100}, false)
	var newest int64
	for _, r := range p.Items {
		newest = max(newest, r.ID)
	}
	// A late batch with a record older than everything shown.
	f.ingest(f.dev, agentproto.LogBatch{Records: []agentproto.LogRecord{{Seq: 9, Time: t0.Add(-time.Minute), Source: "easypatch", Level: "info", Message: "very late"}}})
	tail, err := f.svc.Read(f.ctx, tech, f.dev, agentlogs.Query{After: newest}, true)
	if err != nil || strings.Join(messages(tail.Items), "|") != "very late" {
		t.Fatalf("tail = %v, %v", messages(tail.Items), err)
	}
	// And it takes its place in the merged order.
	p, _ = f.svc.Read(f.ctx, tech, f.dev, agentlogs.Query{Limit: 100}, false)
	if got := messages(p.Items); got[len(got)-1] != "very late" || len(got) != 9 {
		t.Errorf("merged = %v", got)
	}
}

func TestADownloadIsInTimeOrderToo(t *testing.T) {
	f := newFixture(t, 14)
	interleaved(f)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	var out bytes.Buffer
	if n, err := f.svc.Download(f.ctx, tech, f.dev, agentlogs.Query{}, agentlogs.Text, &out); err != nil || n != 8 {
		t.Fatalf("download: %d, %v", n, err)
	}
	var got []string
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		got = append(got, l[strings.LastIndex(l, "] ")+2:])
	}
	// Oldest first; among equal times the one stored first.
	want := []string{"agent 1", "patch 2", "mesh 3", "mesh 4", "patch 4 same time as mesh", "patch 5", "agent 6", "agent 7"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("download = %v", got)
	}
}

func TestStoreTextKeepsRepairDiagnosticsAsRecordsOfTheLogRedactedAndInOrder(t *testing.T) {
	f := newFixture(t, 14)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	at := time.Now().UTC().Truncate(time.Second)
	body := "started\npassword=hunter2hunter2\n\nline with token ert_0123456789abcdef0123456789abcdef\nend\n"
	err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return agentlogs.StoreText(f.ctx, tx, f.dev, "easypatch", "warn", at, body, map[string]string{"repair": "r1", "password": "secret-value"})
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.svc.Read(f.ctx, tech, f.dev, agentlogs.Query{Limit: 100}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Items) != 4 {
		t.Fatalf("records = %v", messages(p.Items))
	}
	// Newest first: the last line first, the lines' order kept by the tie-break.
	if p.Items[0].Message != "end" || p.Items[3].Message != "started" || p.Items[0].Source != "easypatch" || p.Items[0].Level != "warn" || p.Items[0].Attrs["repair"] != "r1" {
		t.Errorf("records = %+v", p.Items)
	}
	for _, r := range p.Items {
		if strings.Contains(r.Message, "hunter2") || strings.Contains(r.Message, "ert_0123456789abcdef") || r.Attrs["password"] == "secret-value" {
			t.Errorf("not redacted: %+v", r)
		}
	}
	// The same source filter as for any record.
	p, _ = f.svc.Read(f.ctx, tech, f.dev, agentlogs.Query{Sources: []string{"meshagent"}}, false)
	if len(p.Items) != 0 {
		t.Errorf("another source shows them: %v", messages(p.Items))
	}
	if f.count(`SELECT stored FROM agent_log_days WHERE device_id = $1`, f.dev) != 4 {
		t.Error("the day's count does not hold them")
	}
}
