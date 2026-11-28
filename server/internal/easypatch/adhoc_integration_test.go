//go:build integration

package easypatch

import (
	"testing"
)

// A Quick Assist session's EasyPatch enrollment (ADR-0080 QA6) against the
// patching engine's stand-in and a real database.
func TestAdHocTokenAndRemoval(t *testing.T) {
	f := newPatching(t)

	// An organization that is not linked gets nothing.
	if g, err := f.svc.AdHocToken(f.ctx, f.globex, "Quick Assist", "x"); g != nil || err != nil {
		t.Fatalf("an unlinked organization got %+v %v", g, err)
	}
	// Patching not set up gets nothing either.
	if g, err := f.unconfigured().AdHocToken(f.ctx, f.acme, "Quick Assist", "x"); g != nil || err != nil {
		t.Fatalf("an engine that is not set up gave %+v %v", g, err)
	}

	before := len(f.ep.Tokens())
	g, err := f.svc.AdHocToken(f.ctx, f.acme, "Quick Assist", "Quick Assist session")
	if err != nil || g == nil || g.Secret == "" || g.Server == "" {
		t.Fatalf("token: %+v %v", g, err)
	}
	// One token, single use, one hour, for the engine site that was made.
	tokens := f.ep.Tokens()
	if len(tokens) != before+1 {
		t.Fatalf("%d tokens, want %d", len(tokens), before+1)
	}
	tk := tokens[len(tokens)-1]
	if tk.ID != g.TokenID || tk.MaxUses != 1 || tk.ExpiresIn != 1 || tk.Site == nil || *tk.Site != g.SiteID || tk.Org != f.epAcme {
		t.Fatalf("token made: %+v for %+v", tk, g)
	}
	// A second session uses the same site, not another.
	g2, err := f.svc.AdHocToken(f.ctx, f.acme, "quick assist", "Quick Assist session")
	if err != nil || g2.SiteID != g.SiteID {
		t.Fatalf("second grant: %+v %v", g2, err)
	}

	// The agent enrolled: an endpoint in that site. Another of the same name
	// in another site is somebody's real computer and stays.
	mine := f.ep.AddEndpoint(f.epAcme, "pc-1", "", "QA-1")
	theirs := f.ep.AddEndpoint(f.epAcme, "pc-1", "", "REAL-1")
	other := f.ep.AddEndpoint(f.epAcme, "pc-2", "", "QA-2")
	hq := f.ep.Site(f.epAcme, "HQ")
	f.ep.Set(func() {
		site := g.SiteID
		mine.Site, mine.SiteName = &site, "Quick Assist"
		other.Site, other.SiteName = &site, "Quick Assist"
		theirs.Site, theirs.SiteName = &hq, "HQ"
	})
	if err := f.svc.AdHocRemove(f.ctx, f.acme, g.TokenID, g.SiteID, "PC-1"); err != nil {
		t.Fatal(err)
	}
	// Asking again changes nothing and is not an error.
	if err := f.svc.AdHocRemove(f.ctx, f.acme, g.TokenID, g.SiteID, "PC-1"); err != nil {
		t.Fatal(err)
	}
	var revoked []string
	f.ep.Set(func() {
		for _, x := range []*struct {
			name    string
			revoked bool
		}{{"mine", mine.Revoked}, {"theirs", theirs.Revoked}, {"other", other.Revoked}} {
			if x.revoked {
				revoked = append(revoked, x.name)
			}
		}
	})
	if len(revoked) != 1 || revoked[0] != "mine" {
		t.Fatalf("revoked %v, want only the session's endpoint", revoked)
	}
	var tokenRevoked bool
	for _, x := range f.ep.Tokens() {
		if x.ID == g.TokenID {
			tokenRevoked = x.Revoked
		}
	}
	if !tokenRevoked {
		t.Fatal("the token was not revoked")
	}
}
