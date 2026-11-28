//go:build integration

package agentsettings_test

import (
	"context"
	"errors"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/agentsettings"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

func TestDocumentViewAndProblems(t *testing.T) {
	w := newWorld(t)
	sa := w.user(rbac.Assignment{Role: rbac.RoleSuperAdmin})
	orgAdmin := w.user(rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: w.acme})

	// hq-1 takes settings and has not applied its document; br-1 takes them and has; gx-1 reported nothing.
	w.exec(`INSERT INTO agent_device_state (device_id, capabilities, doc_version, doc_hash, doc_issued_at, doc_catalog_version, applied_version, not_applied_heartbeats)
		VALUES ($1, '{"accepts":["settings.v1"],"settings":{}}', 2, repeat('a', 64), now(), 1, 1, 3)`, w.dev)
	w.exec(`INSERT INTO agent_device_state (device_id, capabilities, doc_version, doc_hash, doc_issued_at, doc_catalog_version, applied_version, applied_at)
		VALUES ($1, '{"accepts":["settings.v1"],"settings":{}}', 1, repeat('b', 64), now(), 1, 1, now())`, w.branchDev)

	l, err := w.svc.List(context.Background(), sa, w.target(sa, agentsettings.ScopeDevice, w.dev))
	if err != nil {
		t.Fatal(err)
	}
	if l.Document == nil || l.Document.State != agentsettings.DocNotApplied || l.Document.Version != 2 {
		t.Fatalf("hq-1 document = %+v", l.Document)
	}
	l, err = w.svc.List(context.Background(), sa, w.target(sa, agentsettings.ScopeDevice, w.branchDev))
	if err != nil {
		t.Fatal(err)
	}
	if l.Document.State != agentsettings.DocApplied {
		t.Fatalf("br-1 document = %+v", l.Document)
	}
	l, err = w.svc.List(context.Background(), sa, w.target(sa, agentsettings.ScopeDevice, w.globexDev))
	if err != nil {
		t.Fatal(err)
	}
	if l.Document.State != agentsettings.DocUnsupported {
		t.Fatalf("gx-1 document = %+v", l.Document)
	}

	p, err := w.svc.Problems(context.Background(), sa)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.NotApplied) != 1 || p.NotApplied[0].Name != "hq-1" {
		t.Fatalf("not applied = %+v", p.NotApplied)
	}
	names := map[string]bool{}
	for _, d := range p.Unsupported {
		names[d.Name] = true
	}
	if !names["gx-1"] || names["hq-1"] || names["br-1"] {
		t.Fatalf("unsupported = %+v", p.Unsupported)
	}
	if _, err := w.svc.Problems(context.Background(), orgAdmin); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("an organization administrator got %v", err)
	}
}
