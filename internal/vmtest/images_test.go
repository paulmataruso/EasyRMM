package vmtest

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestImageTable(t *testing.T) {
	name := regexp.MustCompile(`^[a-z]+-[0-9]+(\.[0-9]+)?$`)
	hexDigits := map[string]*regexp.Regexp{
		"sha256": regexp.MustCompile(`^[0-9a-f]{64}$`),
		"sha512": regexp.MustCompile(`^[0-9a-f]{128}$`),
	}
	files := map[string]bool{}
	for _, img := range images {
		if !name.MatchString(img.Name) {
			t.Errorf("name %q", img.Name)
		}
		algo, sum, _ := strings.Cut(img.Digest, ":")
		if re := hexDigits[algo]; re == nil || !re.MatchString(sum) {
			t.Errorf("%s: digest %q", img.Name, img.Digest)
		}
		if img.Seed != "nocloud" && img.Seed != "nocloud-net" && img.Seed != SeedISO {
			t.Errorf("%s: seed %q", img.Name, img.Seed)
		}
		if len(img.URLs) == 0 {
			t.Errorf("%s: no URL", img.Name)
		}
		for _, u := range img.URLs {
			if !strings.HasPrefix(u, "https://") || strings.Contains(strings.ToLower(u), "latest") {
				t.Errorf("%s: %s is not a pinned HTTPS URL", img.Name, u)
			}
		}
		if files[img.file()] {
			t.Errorf("%s: cache file %s is taken", img.Name, img.file())
		}
		files[img.file()] = true
	}
	want := []string{"debian-12", "debian-13", "ubuntu-22.04", "ubuntu-24.04", "ubuntu-26.04", "rocky-8", "rocky-9", "rocky-10", "alma-9", "alma-10", "fedora-45"}
	if !slices.Equal(Images(), want) {
		t.Errorf("images %v, want %v", Images(), want)
	}
}

func TestSelected(t *testing.T) {
	t.Setenv(ImageEnv, "")
	if !slices.Equal(Selected(t), Images()) {
		t.Errorf("unset: %v", Selected(t))
	}
	t.Setenv(ImageEnv, "rocky-9, debian-12")
	if got := Selected(t); !slices.Equal(got, []string{"rocky-9", "debian-12"}) {
		t.Errorf("two: %v", got)
	}
	if _, err := lookup("windows-11"); err == nil || !strings.Contains(err.Error(), "debian-12") {
		t.Errorf("unknown image: %v", err)
	}
}

func TestTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "console.log")
	var b strings.Builder
	for i := range 100 {
		b.WriteString("\x1b[0;32m  OK  \x1b[0m] line " + strings.Repeat("x", i%3) + "\r\n")
	}
	b.WriteString("\x1b[?25lthe end\n")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	got := tail(path, 3)
	if want := "  OK  ] line xx\n  OK  ] line \nthe end\n"; got != want {
		t.Errorf("tail %q, want %q", got, want)
	}
	if tail(filepath.Join(t.TempDir(), "missing"), 3) != "" {
		t.Error("a missing log has a tail")
	}
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if tail(empty, 3) != "" {
		t.Error("an empty log has a tail")
	}
}

func TestKeepConsole(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	console := filepath.Join(t.TempDir(), "console.log")
	if err := keepConsole(dir, "TestSmoke/debian-12", console); err != nil {
		t.Errorf("a missing console: %v", err)
	}
	if err := os.WriteFile(console, []byte("boot\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := keepConsole(dir, "TestSmoke/debian-12", console); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "TestSmoke_debian-12.console.log")); err != nil || string(b) != "boot\n" {
		t.Errorf("kept %q, %v", b, err)
	}
}

func TestShellQuote(t *testing.T) {
	for _, s := range []string{"plain", "it's", "a b", `$(x) "y" \z`, "", "'"} {
		out, err := exec.Command("sh", "-c", "printf '%s' "+shellQuote(s)).Output()
		if err != nil || string(out) != s {
			t.Errorf("%q came back as %q (%v)", s, out, err)
		}
	}
}
