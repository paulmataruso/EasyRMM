package templates

import (
	"strings"
	"testing"
)

func TestTemplatesAreOurOwnAndSafe(t *testing.T) {
	all, err := All()
	if err != nil || len(all) < 4 {
		t.Fatalf("%d templates: %v", len(all), err)
	}
	kinds := map[string]bool{}
	for _, tp := range all {
		kinds[tp.Kind] = true
		if tp.Author != "EasyRMM" || tp.LicenceClass != "ORIGINAL" {
			t.Errorf("%s: author %q, class %q", tp.ID, tp.Author, tp.LicenceClass)
		}
		seen := map[string]bool{}
		for _, s := range tp.Sections {
			if s.ID == "" || s.Heading == "" || seen[s.ID] {
				t.Errorf("%s: bad or repeated section %q", tp.ID, s.ID)
			}
			seen[s.ID] = true
			if s.Generate != "" && s.Body != "" {
				t.Errorf("%s/%s: a generated section holds text", tp.ID, s.ID)
			}
			switch s.Generate {
			case "", "scope", "requirements", "poam", "score":
			default:
				t.Errorf("%s/%s: unknown generator %q", tp.ID, s.ID, s.Generate)
			}
			low := strings.ToLower(s.Heading + " " + s.Body)
			for _, bad := range []string{"compliant", "certified", "audit-ready", "dod ", "cis "} {
				if strings.Contains(low, bad) {
					t.Errorf("%s/%s says %q", tp.ID, s.ID, bad)
				}
			}
		}
	}
	for _, k := range []string{"ssp", "policy", "procedure", "plan"} {
		if !kinds[k] {
			t.Errorf("no %s template", k)
		}
	}
	if _, err := Get("ssp-v1"); err != nil {
		t.Error(err)
	}
	if _, err := Get("nope"); err == nil {
		t.Error("a missing template was found")
	}
}
