package main

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/compliance/content"
)

// copyContent writes the embedded content into a temporary directory.
func copyContent(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	err := fs.WalkDir(content.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dir, p), 0o750)
		}
		b, err := fs.ReadFile(content.FS, p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, p), b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func lint(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestCleanDevContentPasses(t *testing.T) {
	code, out, errs := lint(t, "-dir", copyContent(t))
	if code != 0 || !strings.Contains(out, "clean for the dev edition") {
		t.Errorf("%d %s %s", code, out, errs)
	}
}

// The golden case: a deliberately restricted pack passes a dev build and
// fails a commercial one, naming the file, until it is removed.
func TestRestrictedFixtureFailsCommercial(t *testing.T) {
	dir := copyContent(t)
	body := `{"pack":{"key":"fixture-restricted","version":"1","kind":"framework","title":"A fixture","licence_class":"RESTRICTED","source_id":"nist-csf-2","review_state":"none"},` +
		`"framework":{"key":"fixture-restricted","version":"1","title":"t","publisher":"p","source_id":"nist-csf-2","text_policy":"ids_only"},"requirements":[]}`
	if err := os.WriteFile(filepath.Join(dir, "packs", "fixture-restricted.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// Not in the manifest yet: even a dev build fails.
	if code, _, errs := lint(t, "-dir", dir); code != 1 || !strings.Contains(errs, "packs/fixture-restricted.json: not in manifest.json") {
		t.Errorf("unlisted: %d %s", code, errs)
	}
	if code, out, _ := lint(t, "-dir", dir, "-update"); code != 0 || !strings.Contains(out, "updated") {
		t.Fatalf("update: %d %s", code, out)
	}
	if code, _, errs := lint(t, "-dir", dir); code != 0 {
		t.Errorf("dev after update: %d %s", code, errs)
	}
	code, _, errs := lint(t, "-dir", dir, "-edition", "commercial")
	if code != 1 || !strings.Contains(errs, "packs/fixture-restricted.json: licence class RESTRICTED is not allowed in a commercial build") {
		t.Errorf("commercial: %d %s", code, errs)
	}
	if err := os.Remove(filepath.Join(dir, "packs", "fixture-restricted.json")); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := lint(t, "-dir", dir, "-update"); code != 0 {
		t.Fatalf("update after removal: %d %s", code, out)
	}
	// What remains fails a commercial build only for the two packs that wait for review.
	_, _, errs = lint(t, "-dir", dir, "-edition", "commercial")
	if strings.Contains(errs, "fixture-restricted") || strings.Count(errs, "review is still needed") != 2 {
		t.Errorf("%s", errs)
	}
}

func TestBannedMarkerAndBadFlags(t *testing.T) {
	dir := copyContent(t)
	p := filepath.Join(dir, "controls", "linux.json")
	b, _ := os.ReadFile(p) //nolint:gosec // a test file
	b = []byte(strings.Replace(string(b), `"remediation_text": "Make this true`, `"remediation_text": "Wazuh rule: Make this true`, 1))
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := lint(t, "-dir", dir, "-update"); code != 0 {
		t.Fatal(errs)
	}
	if code, _, errs := lint(t, "-dir", dir); code != 1 || !strings.Contains(errs, `banned marker "Wazuh"`) {
		t.Errorf("%d %s", code, errs)
	}
	if code, _, _ := lint(t, "-edition", "free"); code != 2 {
		t.Errorf("a bad edition: %d", code)
	}
	if code, _, _ := lint(t, "-nonsense"); code != 2 {
		t.Errorf("a bad flag: %d", code)
	}
	if code, _, _ := lint(t, "-dir", t.TempDir()); code != 1 {
		t.Errorf("an empty directory: %d", code)
	}
	if code, _, _ := lint(t, "-dir", t.TempDir(), "-update"); code != 1 {
		t.Errorf("update of an empty directory: %d", code)
	}
}

func TestEmbeddedContentIsClean(t *testing.T) {
	if code, _, errs := lint(t); code != 0 {
		t.Errorf("the embedded content: %s", errs)
	}
}
