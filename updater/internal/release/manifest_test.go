package release_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/updater/internal/release"
	"github.com/paulmataruso/easyrmm/updater/internal/release/releasetest"
)

const (
	testCommit = "7fc6602ea97f32b40fa0bf4496e58694d536be7c"
	digestA    = releasetest.Digest
)

func encode(t *testing.T, fields map[string]any) []byte {
	t.Helper()
	b, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseManifest(t *testing.T) {
	want := releasetest.NewManifest("v1.2.3-rc.1", testCommit)
	m, err := release.ParseManifest(want.JSON())
	if err != nil {
		t.Fatal(err)
	}
	if m.Version.String() != "v1.2.3-rc.1" || m.Commit != testCommit || m.PostgresMajor != 18 ||
		m.BundleFile != "easyrmm-v1.2.3-rc.1-deploy.tar.gz" || m.BundleSHA256 != want.BundleSHA256 ||
		m.Server != want.ServerImage() || m.Engine != want.Engine || m.Postgres != want.Postgres ||
		m.MeshCentral != want.MeshCentral || m.Authentik != want.Authentik {
		t.Fatalf("parsed %+v", m)
	}
	if got := m.ServerRepository(); got != "ghcr.io/paulmataruso/easyrmm-server" {
		t.Errorf("ServerRepository = %q", got)
	}
	if got := m.ServerTagAndDigest(); got != "1.2.3-rc.1"+digestA {
		t.Errorf("ServerTagAndDigest = %q", got)
	}
	all := m.Images(true)
	if len(all) != 5 || !slices.IsSorted(all) || !slices.Contains(all, m.Authentik) {
		t.Errorf("Images(true) = %v", all)
	}
	without := m.Images(false)
	if len(without) != 4 || slices.Contains(without, m.Authentik) {
		t.Errorf("Images(false) = %v", without)
	}
}

// A required upgrade stop: a release or a release candidate below the
// manifest's version; a manifest without one has none.
func TestParseManifestUpgradeFrom(t *testing.T) {
	for _, stop := range []string{"v1.2.0", "v1.2.3-rc.2", ""} {
		mf := releasetest.NewManifest("v1.2.3", testCommit)
		mf.UpgradeFrom = stop
		m, err := release.ParseManifest(mf.JSON())
		if err != nil {
			t.Fatalf("%q: %v", stop, err)
		}
		if m.UpgradeFrom.String() != stop {
			t.Errorf("UpgradeFrom = %q, want %q", m.UpgradeFrom, stop)
		}
	}
}

// A later manifest's form is read as this one's: what it adds is ignored
// (ADR-0052, "Required upgrade stops").
func TestParseManifestLaterSchema(t *testing.T) {
	f := manifestFields(t, "v1.2.3")
	f["schemaVersion"] = release.SchemaVersion + 1
	f["somethingNew"] = map[string]any{"a": 1}
	m, err := release.ParseManifest(encode(t, f))
	if err != nil || m.Version.String() != "v1.2.3" {
		t.Fatalf("%v %+v", err, m)
	}
}

func TestParseManifestWithoutAuthentik(t *testing.T) {
	mf := releasetest.NewManifest("v1.2.3", testCommit)
	mf.Authentik = ""
	m, err := release.ParseManifest(mf.JSON())
	if err != nil {
		t.Fatal(err)
	}
	if m.Authentik != "" {
		t.Errorf("Authentik = %q", m.Authentik)
	}
	if len(m.Images(true)) != 4 {
		t.Errorf("Images(true) without Authentik = %v", m.Images(true))
	}
}

func TestParseManifestRegistryWithPort(t *testing.T) {
	mf := releasetest.NewManifest("v1.2.3", testCommit)
	mf.Server = "10.0.2.2:41234/easyrmm-server"
	m, err := release.ParseManifest(mf.JSON())
	if err != nil {
		t.Fatal(err)
	}
	if m.ServerRepository() != "10.0.2.2:41234/easyrmm-server" || m.ServerTagAndDigest() != "1.2.3"+digestA {
		t.Errorf("repository %q, tag and digest %q", m.ServerRepository(), m.ServerTagAndDigest())
	}
}

// An image the bundle names besides the five the manifest names on their
// own is in the list a deployment must run.
func TestParseManifestMoreImages(t *testing.T) {
	f := manifestFields(t, "v1.2.3")
	extra := "docker.io/library/redis:8.2" + digestA
	images := append(slices.Clone(f["images"].([]string)), extra)
	slices.Sort(images)
	f["images"] = images
	m, err := release.ParseManifest(encode(t, f))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(m.Images(false), extra) {
		t.Errorf("Images(false) = %v", m.Images(false))
	}
}

func TestParseManifestRefuses(t *testing.T) {
	set := func(path string, value any) func(map[string]any) {
		return func(f map[string]any) {
			parts := strings.Split(path, ".")
			m := f
			for _, p := range parts[:len(parts)-1] {
				m = m[p].(map[string]any)
			}
			if value == nil {
				delete(m, parts[len(parts)-1])
				return
			}
			m[parts[len(parts)-1]] = value
		}
	}
	images := func(change func([]string) []string) func(map[string]any) {
		return func(f map[string]any) { f["images"] = change(slices.Clone(f["images"].([]string))) }
	}
	server := "ghcr.io/paulmataruso/easyrmm-server:1.2.3" + digestA
	for name, change := range map[string]func(map[string]any){
		"no schema version":           set("schemaVersion", nil),
		"schema version 1":            set("schemaVersion", 1),
		"upgradeFrom an edge build":   set("upgradeFrom", "v1.2.2-edge.400.1"),
		"upgradeFrom itself":          set("upgradeFrom", "v1.2.3"),
		"upgradeFrom above it":        set("upgradeFrom", "v1.3.0"),
		"upgradeFrom of another form": set("upgradeFrom", "1.2.0"),
		"no version":                  set("version", nil),
		"a version of another form":   set("version", "edge-1df9b49"),
		"easyrmm.version differs":     set("easyrmm.version", "v1.2.4"),
		"a short commit":              set("commit", "7fc6602"),
		"an uppercase commit":         set("commit", strings.ToUpper(testCommit)),
		"no commit":                   set("commit", nil),
		"another bundle name":         set("bundle.file", "easyrmm-v9.9.9-deploy.tar.gz"),
		"a bundle path":               set("bundle.file", "../easyrmm-v1.2.3-deploy.tar.gz"),
		"a short bundle digest":       set("bundle.sha256", "ffff"),
		"no PostgreSQL major":         set("postgres.major", 0),
		"a server image by tag":       set("easyrmm.image", "ghcr.io/paulmataruso/easyrmm-server:1.2.3"),
		"a server of another tag":     set("easyrmm.image", "ghcr.io/paulmataruso/easyrmm-server:1.2.4"+digestA),
		"a server without a tag":      set("easyrmm.image", "ghcr.io/paulmataruso/easyrmm-server"+digestA),
		"an engine by tag":            set("easypatch.image", "ghcr.io/paulmataruso/easypatch-server:1.12.1"),
		"no engine":                   set("easypatch.image", nil),
		"PostgreSQL by tag":           set("postgres.image", "postgres:18"),
		"MeshCentral by tag":          set("meshcentral.image", "ghcr.io/ylianst/meshcentral:1.3.1"),
		"no Authentik section":        set("authentik", nil),
		"Authentik not said":          set("authentik.included", nil),
		"Authentik without image":     set("authentik.image", nil),
		"Authentik by tag":            set("authentik.image", "ghcr.io/goauthentik/server:2026.8.5"),
		"Authentik's image, excluded": set("authentik.included", false),
		"an image with spaces":        set("meshcentral.image", "ghcr.io/ylianst/mesh central:1"+digestA),
		"an uppercase repository":     set("meshcentral.image", "ghcr.io/Ylianst/meshcentral:1.3.1"+digestA),
		"no images":                   set("images", nil),
		"the server not among them": images(func(l []string) []string {
			return slices.DeleteFunc(l, func(s string) bool { return s == server })
		}),
		"images out of order":        images(func(l []string) []string { slices.Reverse(l); return l }),
		"an image twice":             images(func(l []string) []string { return slices.Insert(l, 0, l[0]) }),
		"an image by tag among them": images(func(l []string) []string { return append([]string{"alpine:3"}, l...) }),
	} {
		f := manifestFields(t, "v1.2.3")
		change(f)
		if m, err := release.ParseManifest(encode(t, f)); err == nil {
			t.Errorf("%s: parsed %+v", name, m)
		}
	}
	for name, data := range map[string]string{
		"not JSON":        "{",
		"an array":        "[]",
		"trailing data":   string(releasetest.NewManifest("v1.2.3", testCommit).JSON()) + "{}",
		"a huge manifest": `{"x":"` + strings.Repeat("a", release.MaxManifestBytes) + `"}`,
	} {
		if m, err := release.ParseManifest([]byte(data)); err == nil {
			t.Errorf("%s: parsed %+v", name, m)
		}
	}
}

// manifestFields is a well-formed manifest as JSON decodes it, with its
// images as strings, for a test to change.
func manifestFields(t *testing.T, version string) map[string]any {
	t.Helper()
	var f map[string]any
	if err := json.Unmarshal(releasetest.NewManifest(version, testCommit).JSON(), &f); err != nil {
		t.Fatal(err)
	}
	images := f["images"].([]any)
	list := make([]string, len(images))
	for i, img := range images {
		list[i] = img.(string)
	}
	f["images"] = list
	return f
}
