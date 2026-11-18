//go:build !windows

package inventory

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// packages reads the installed packages from the first package database
// found: dpkg, apk and pacman as files, RPM through `rpm -qa`.
func (c Collector) packages(ctx context.Context) (string, []agentproto.Package) {
	if s := c.read("/var/lib/dpkg/status"); s != "" {
		return "dpkg", finish(dpkg(s))
	}
	if s := c.read("/lib/apk/db/installed"); s != "" {
		return "apk", finish(apk(s))
	}
	if list, ok := c.pacman(); ok {
		return "pacman", finish(list)
	}
	if list, ok := c.rpm(ctx); ok {
		return "rpm", finish(list)
	}
	return "", []agentproto.Package{}
}

// finish sorts, removes duplicates and caps a package list.
// stanzas splits a file of "Key: value" blocks separated by blank lines,
// calling fn with each block's fields. Continuation lines (starting with a
// space) are skipped.
func stanzas(s, sep string, fn func(map[string]string)) {
	fields := map[string]string{}
	flush := func() {
		if len(fields) > 0 {
			fn(fields)
			fields = map[string]string{}
		}
	}
	for line := range strings.Lines(s) {
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		if k, v, ok := strings.Cut(line, sep); ok {
			fields[k] = strings.TrimSpace(v)
		}
	}
	flush()
}

// dpkg reads /var/lib/dpkg/status, keeping installed packages only.
func dpkg(s string) []agentproto.Package {
	var out []agentproto.Package
	stanzas(s, ":", func(f map[string]string) {
		st := strings.Fields(f["Status"])
		if f["Package"] == "" || len(st) != 3 || st[2] != "installed" {
			return
		}
		out = append(out, agentproto.Package{Name: f["Package"], Version: f["Version"], Arch: f["Architecture"]})
	})
	return out
}

// apk reads Alpine's /lib/apk/db/installed (P: name, V: version, A: arch).
func apk(s string) []agentproto.Package {
	var out []agentproto.Package
	stanzas(s, ":", func(f map[string]string) {
		if f["P"] != "" {
			out = append(out, agentproto.Package{Name: f["P"], Version: f["V"], Arch: f["A"]})
		}
	})
	return out
}

// pacman reads Arch Linux's /var/lib/pacman/local/*/desc.
func (c Collector) pacman() ([]agentproto.Package, bool) {
	dir := c.path("/var/lib/pacman/local")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, false
	}
	var out []agentproto.Package
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name(), "desc")) //nolint:gosec // entries of the package database directory
		if err != nil {
			continue
		}
		f := pacmanDesc(string(b))
		if f["NAME"] != "" {
			out = append(out, agentproto.Package{Name: f["NAME"], Version: f["VERSION"], Arch: f["ARCH"]})
		}
	}
	return out, true
}

// pacmanDesc reads "%KEY%\nvalue\n\n" blocks; only the first value line
// counts.
func pacmanDesc(s string) map[string]string {
	out := map[string]string{}
	key := ""
	for line := range strings.Lines(s) {
		line = strings.TrimSpace(line)
		switch {
		case len(line) > 2 && line[0] == '%' && line[len(line)-1] == '%':
			key = line[1 : len(line)-1]
		case line == "":
			key = ""
		case key != "":
			if _, seen := out[key]; !seen {
				out[key] = line
			}
		}
	}
	return out
}

// rpmQuery prints name, [epoch:]version-release and arch, tab-separated.
const rpmQuery = `%{NAME}\t%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\t%{ARCH}\n`

// rpm lists RPM packages with the rpm command.
func (c Collector) rpm(ctx context.Context) ([]agentproto.Package, bool) {
	if _, err := os.Stat(c.path("/var/lib/rpm")); err != nil {
		if _, err := os.Stat(c.path("/usr/lib/sysimage/rpm")); err != nil {
			return nil, false
		}
	}
	look := c.LookPath
	if look == nil {
		look = lookPath
	}
	bin, err := look("rpm")
	if err != nil {
		return nil, false
	}
	run := c.Run
	if run == nil {
		run = output
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	b, err := run(ctx, bin, "-qa", "--qf", rpmQuery)
	if err != nil {
		return nil, false
	}
	var out []agentproto.Package
	for line := range strings.Lines(string(b)) {
		f := strings.Split(strings.TrimRight(line, "\r\n"), "\t")
		if len(f) == 3 && f[0] != "" && f[0] != "gpg-pubkey" {
			out = append(out, agentproto.Package{Name: f[0], Version: f[1], Arch: f[2]})
		}
	}
	return out, true
}

// lookPath finds a command in the system's fixed directories, never in
// whatever PATH the agent was started with.
func lookPath(name string) (string, error) {
	for _, dir := range []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin"} {
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", errors.New("not found")
}

func output(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // a fixed command found in system directories
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	return cmd.Output()
}
