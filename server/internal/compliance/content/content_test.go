package content_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/paulmataruso/easyrmm/server/internal/compliance"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/content"
)

// tree copies the embedded content into a map file system a test can alter.
func tree(t *testing.T) fstest.MapFS {
	t.Helper()
	m := fstest.MapFS{}
	err := fs.WalkDir(content.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(content.FS, p)
		m[p] = &fstest.MapFile{Data: b}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func has(errs []error, sub string) bool {
	for _, e := range errs {
		if strings.Contains(e.Error(), sub) {
			return true
		}
	}
	return false
}

func TestEmbeddedContentIsCleanForDev(t *testing.T) {
	if errs := content.Check(content.FS, compliance.EditionDev); len(errs) > 0 {
		t.Fatalf("%v", errs)
	}
}

// Review that is still needed stops a commercial build, and says which file.
func TestCommercialNeedsClearedReview(t *testing.T) {
	errs := content.Check(content.FS, compliance.EditionCommercial)
	if !has(errs, "packs/cis-xref.json: review is still needed") || !has(errs, "packs/gdpr-indicative.json: review is still needed") {
		t.Errorf("%v", errs)
	}
	if len(errs) != 2 {
		t.Errorf("only those two packs wait for review, got %v", errs)
	}
}

func TestManifestHashesAndCompleteness(t *testing.T) {
	m := tree(t)
	m["packs/nist-csf-2.json"].Data = append(m["packs/nist-csf-2.json"].Data, ' ')
	if errs := content.Check(m, compliance.EditionDev); !has(errs, "packs/nist-csf-2.json: SHA-256 does not match") {
		t.Errorf("a changed file: %v", errs)
	}
	m = tree(t)
	m["packs/sneaked-in.json"] = &fstest.MapFile{Data: []byte(`{}`)}
	if errs := content.Check(m, compliance.EditionDev); !has(errs, "packs/sneaked-in.json: not in manifest.json") {
		t.Errorf("a file outside the manifest: %v", errs)
	}
	m = tree(t)
	delete(m, "packs/nist-csf-2.json")
	if errs := content.Check(m, compliance.EditionDev); !has(errs, "in the manifest but not in the content") {
		t.Errorf("a missing file: %v", errs)
	}
}

// A restricted class stops a commercial build and not a dev one.
func TestRestrictedClassesAreRefusedInCommercial(t *testing.T) {
	for _, cls := range []compliance.Class{compliance.ClassNoncommercial, compliance.ClassCommercialRequired, compliance.ClassRestricted} {
		m := tree(t)
		mf, _ := content.ReadManifest(m)
		for i := range mf.Files {
			if mf.Files[i].Path == "packs/nist-csf-2.json" {
				mf.Files[i].LicenceClass = cls
			}
		}
		b, _ := json.Marshal(mf)
		m["manifest.json"].Data = b
		if errs := content.Check(m, compliance.EditionDev); has(errs, "not allowed") {
			t.Errorf("%s: dev refused it: %v", cls, errs)
		}
		if errs := content.Check(m, compliance.EditionCommercial); !has(errs, "packs/nist-csf-2.json: licence class "+string(cls)+" is not allowed in a commercial build") {
			t.Errorf("%s: %v", cls, errs)
		}
	}
}

func TestBannedMarkersAndDerivedContent(t *testing.T) {
	for _, marker := range []string{"Center for Internet Security", "CIS Benchmark", "Wazuh", "GNU General Public License"} {
		m := tree(t)
		m["controls/linux.json"].Data = []byte(strings.Replace(string(m["controls/linux.json"].Data),
			`"remediation_text": "Make this true`, `"remediation_text": "`+marker+`: Make this true`, 1))
		errs := content.Check(m, compliance.EditionDev)
		if !has(errs, "banned marker \""+marker+"\" in field \"remediation_text\"") {
			t.Errorf("%s: %v", marker, errs)
		}
	}
	// The cross-reference number field is exempt, and the source's publisher is not a text field.
	m := tree(t)
	m["packs/cis-xref.json"].Data = []byte(strings.Replace(string(m["packs/cis-xref.json"].Data), `"xref": "1.1.1"`, `"xref": "CIS Benchmark 1.1.1"`, 1))
	if errs := content.Check(m, compliance.EditionDev); has(errs, "banned marker") {
		t.Errorf("the xref field is exempt: %v", errs)
	}
	m = tree(t)
	m["controls/linux.json"].Data = []byte(strings.Replace(string(m["controls/linux.json"].Data), `"derived_from_content": false`, `"derived_from_content": true`, 1))
	if errs := content.Check(m, compliance.EditionDev); !has(errs, "derived_from_content true") {
		t.Errorf("%v", errs)
	}
}

func TestManifestEntryNeedsAuthorAndSource(t *testing.T) {
	m := tree(t)
	mf, _ := content.ReadManifest(m)
	mf.Files[0].Author = ""
	b, _ := json.Marshal(mf)
	m["manifest.json"].Data = b
	if errs := content.Check(m, compliance.EditionDev); !has(errs, "needs a named author") {
		t.Errorf("%v", errs)
	}
}

func TestNoticeRegeneratesAndListsAttribution(t *testing.T) {
	m := tree(t)
	m["NOTICE.generated"].Data = []byte("stale\n")
	if errs := content.Check(m, compliance.EditionDev); !has(errs, "NOTICE.generated is out of date") {
		t.Errorf("%v", errs)
	}
	m = tree(t)
	att := "Example data by Example Org, CC BY 4.0"
	m["sources.json"].Data = []byte(`{"sources":[{"id":"ex","title":"Example","publisher":"Example Org","url":"https://example.org","licence_class":"ATTRIBUTION_REQUIRED","licence_spdx":"CC-BY-4.0","licence_note":"n","attribution":"` + att + `","retrieved_at":"2026-01-01","sha256":null,"review_state":"none"}]}`)
	n, err := content.Notice(m)
	if err != nil || !strings.Contains(n, att) || !strings.Contains(n, "CC-BY-4.0") {
		t.Errorf("%q, %v", n, err)
	}
	if n, _ := content.Notice(content.FS); !strings.Contains(n, "No third-party content") {
		t.Errorf("%q", n)
	}
}

func TestUpdateWritesHashesThatCheck(t *testing.T) {
	m := tree(t)
	m["packs/nist-csf-2.json"].Data = append(m["packs/nist-csf-2.json"].Data, '\n')
	mf, notice, err := content.Update(m)
	if err != nil {
		t.Fatal(err)
	}
	m["manifest.json"].Data, m["NOTICE.generated"].Data = mf, notice
	if errs := content.Check(m, compliance.EditionDev); len(errs) > 0 {
		t.Errorf("after update: %v", errs)
	}
	// A new file takes its class from its header, and a restricted one fails commercial at once.
	m["packs/new.json"] = &fstest.MapFile{Data: []byte(`{"pack":{"key":"new","version":"1","kind":"framework","title":"t","licence_class":"RESTRICTED","source_id":"s","review_state":"none"}}`)}
	mf, _, err = content.Update(m)
	if err != nil || !strings.Contains(string(mf), `"RESTRICTED"`) {
		t.Errorf("%s, %v", mf, err)
	}
}

func TestSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := tree(t)
	if err := content.VerifySignature(m, compliance.EditionDev, ""); err != nil {
		t.Errorf("dev takes an unsigned manifest: %v", err)
	}
	if err := content.VerifySignature(m, compliance.EditionCommercial, hex.EncodeToString(pub)); err == nil {
		t.Error("commercial took an unsigned manifest")
	}
	m["manifest.sig"] = &fstest.MapFile{Data: []byte(hex.EncodeToString(ed25519.Sign(priv, m["manifest.json"].Data)))}
	if err := content.VerifySignature(m, compliance.EditionCommercial, hex.EncodeToString(pub)); err != nil {
		t.Errorf("a good signature: %v", err)
	}
	if err := content.VerifySignature(m, compliance.EditionCommercial, ""); err == nil {
		t.Error("no key to check with")
	}
	m["manifest.json"].Data = append(m["manifest.json"].Data, ' ')
	if err := content.VerifySignature(m, compliance.EditionCommercial, hex.EncodeToString(pub)); err == nil {
		t.Error("a changed manifest verified")
	}
	m["manifest.sig"].Data = []byte("zz")
	if err := content.VerifySignature(m, compliance.EditionDev, hex.EncodeToString(pub)); err == nil {
		t.Error("a bad signature file")
	}
}
