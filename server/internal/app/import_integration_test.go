//go:build integration

package app

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

// TestImportEasyPatch runs `easyrmm-server import-easypatch` as the import
// script does (ADR-0045), and prints its report.
func TestImportEasyPatch(t *testing.T) {
	inst := testdb.New(t)
	cfg := runConfig(t, inst)
	ctx := context.Background()
	var out bytes.Buffer

	key := bytes.Repeat([]byte{9}, 32)
	engine := eptest.NewEngine(t, key)
	contoso := engine.Org("Contoso")
	engine.Site(contoso, "HQ")
	engine.Org("contoso")
	away := engine.Org("Away")
	engine.ChangeOrganization(away, func(o *eptest.OrgInfo) { o.TimeZone = "Nowhere/Else" })
	gone := engine.Org("Gone")
	engine.ChangeOrganization(gone, func(o *eptest.OrgInfo) { now := time.Now(); o.Active, o.ArchivedAt = false, &now })
	cfg.Patching = config.Patching{URL: engine.URL(), Key: key}

	if err := ImportEasyPatch(ctx, cfg, discard(), &out); err != nil {
		t.Fatal(err)
	}
	want := `Imported 3 organization(s) (3 new in EasyRMM, 0 joined EasyRMM's of the same name) and 1 site(s) (1 new, 0 joined).
  organization "Away" (new)
  organization "Contoso" (new)
    site "HQ" (new)
  organization "contoso", now "contoso (2)" (new): EasyRMM's names are unique ignoring case
Not imported: 1 archived organization(s) and 0 archived site(s), which stay archived in the patching engine.
Note: Organization "Away": its time zone "Nowhere/Else" is not one EasyRMM knows, so it uses UTC.
`
	if out.String() != want {
		t.Fatalf("report:\n%s\nwant:\n%s", out.String(), want)
	}

	// Again, once EasyRMM has them all.
	out.Reset()
	if err := ImportEasyPatch(ctx, cfg, discard(), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "Imported 3 organization(s) (0 new in EasyRMM, 3 joined EasyRMM's of the same name) and 1 site(s) (0 new, 1 joined).\n") ||
		!strings.Contains(out.String(), `organization "contoso", now "contoso (2)" (joined)`) || !strings.Contains(out.String(), `site "HQ" (joined)`) {
		t.Fatalf("again:\n%s", out.String())
	}

	// A renamed site, and a report that cannot be written.
	engine.Site(contoso, "hq")
	out.Reset()
	if err := ImportEasyPatch(ctx, cfg, discard(), &out); err != nil || !strings.Contains(out.String(), `site "hq", now "hq (2)" (new)`) {
		t.Fatalf("renamed site: %v\n%s", err, out.String())
	}
	if err := ImportEasyPatch(ctx, cfg, discard(), failWriter{}); err == nil {
		t.Fatal("a failed write is not reported")
	}

	// Settings it cannot work with, and an engine that refuses it.
	for name, broken := range map[string]func(c *config.Config){
		"migration URL": func(c *config.Config) { c.DatabaseMigrationURL = "postgres://%zz" },
		"database URL":  func(c *config.Config) { c.DatabaseURL = "postgres://%zz" },
		"key":           func(c *config.Config) { c.Patching.Key = []byte{1} },
		"engine URL":    func(c *config.Config) { c.Patching.URL = "ftp://" + unusedAddr(t) },
		"refused":       func(c *config.Config) { c.Patching.Key = bytes.Repeat([]byte{8}, 32) },
	} {
		c := *cfg
		broken(&c)
		start := time.Now()
		if err := ImportEasyPatch(ctx, &c, discard(), &out); err == nil {
			t.Errorf("%s: no error", name)
		}
		// Refused at once: only an engine that does not answer is waited for.
		if d := time.Since(start); d > 20*time.Second {
			t.Errorf("%s: %s", name, d)
		}
	}

	// The engine unreachable: refused before anything changes.
	cfg.Patching.URL = "http://" + unusedAddr(t)
	short, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := ImportEasyPatch(short, cfg, discard(), &out); err == nil {
		t.Fatal("an unreachable engine is not reported")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, context.Canceled }
