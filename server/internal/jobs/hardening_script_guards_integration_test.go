//go:build integration

package jobs

// The hardening script's guards (ADR-0051), in the containers of
// TestCheckInContainers: the job's time, the steps a cancel stops, what a
// record says of packages, generated files and links, and what apply and
// undo refuse.

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// token is a package as the script records it (its PKG_TOKEN): the name it
// lists the package by, then its version and install time.
func (c *scriptContainer) token(t *testing.T, pkg string) string {
	t.Helper()
	if c.has(t, "dpkg-query") {
		return strings.TrimSpace(c.sh(t, `n=$(dpkg-query -W -f='${binary:Package}' `+pkg+`) && `+
			`printf '%s/%s/%s' "$n" "$(dpkg-query -W -f='${Version}' "$n")" "$(stat -c %Y /var/lib/dpkg/info/$n.list)"`))
	}
	return strings.TrimSpace(c.sh(t, `n=$(rpm -q --qf '%{NAME}.%{ARCH}' `+pkg+`) && `+
		`printf '%s/%s' "$n" "$(rpm -q --qf '%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}/%{INSTALLTIME}' "$n")"`))
}

// record writes MODULE's record by hand, as apply would have: its lines
// (fields separated by tabs) and a done mark.
func (c *scriptContainer) record(t *testing.T, module string, lines ...string) {
	t.Helper()
	q := make([]string, len(lines))
	for i, l := range lines {
		q[i] = "'" + strings.ReplaceAll(l, "'", `'"'"'`) + "'"
	}
	dir := stateDir + "/modules/" + module
	c.sh(t, "mkdir -p "+dir+"/files && printf '%s\\n' 'format 1' "+strings.Join(q, " ")+" >"+dir+"/manifest && date >"+dir+"/done")
}

// buildDeb builds a package offline (where dpkg-deb is), as
// /tmp/NAME.deb: its control fields after Package, Version and the like,
// then its maintainer scripts and files, each "PATH CONTENT".
func (c *scriptContainer) buildDeb(t *testing.T, name, control string, files ...string) {
	t.Helper()
	dir := "/tmp/" + name
	script := "rm -rf " + dir + " && mkdir -p " + dir + "/DEBIAN && printf 'Package: " + name +
		"\\nVersion: 1\\nArchitecture: all\\nMaintainer: EasyRMM tests <tests@example.invalid>\\nDescription: a stand-in\\n" + control + "' >" + dir + "/DEBIAN/control"
	for _, f := range files {
		path, content, _ := strings.Cut(f, " ")
		script += " && mkdir -p \"$(dirname " + dir + path + ")\" && printf '" + content + "' >" + dir + path
		if strings.HasPrefix(path, "/DEBIAN/") && path != "/DEBIAN/conffiles" {
			script += " && chmod 0755 " + dir + path
		}
	}
	c.sh(t, script+" && dpkg-deb --build "+dir+" /tmp/"+name+".deb >/dev/null && rm -rf "+dir)
}

// standIn puts a stand-in for COMMAND first in the script's PATH: CASES
// (a case statement's arms, on " ARGS "), then the real command.
func (c *scriptContainer) standIn(t *testing.T, command, cases string) {
	t.Helper()
	real := strings.TrimSpace(c.sh(t, "PATH=/usr/sbin:/usr/bin:/sbin:/bin command -v "+command))
	c.sh(t, "printf '%s\\n' '#!/bin/sh' 'case \" $* \" in' '"+strings.ReplaceAll(cases, "'", `'"'"'`)+"' 'esac' 'exec "+real+" \"$@\"' >/usr/local/sbin/"+
		command+" && chmod 0755 /usr/local/sbin/"+command)
}

// packageManager is the command that installs here, and the argument of
// its refresh of the package lists.
func (c *scriptContainer) packageManager(t *testing.T) (string, string) {
	t.Helper()
	if c.has(t, "apt-get") {
		return "apt-get", "update"
	}
	return "dnf", "makecache"
}

// slowRefresh makes the package lists' refresh, apply's first package step,
// write its PID to /tmp/easyrmm-test-step and wait five minutes.
func (c *scriptContainer) slowRefresh(t *testing.T) string {
	t.Helper()
	pm, refresh := c.packageManager(t)
	c.sh(t, "rm -f /tmp/easyrmm-test-step")
	c.standIn(t, pm, `*" `+refresh+` "*) echo $$ >/tmp/easyrmm-test-step; exec sleep 300 ;;`)
	return pm
}

// stepGone: the process slowRefresh started is gone (or a zombie).
const stepGone = `p=$(cat /tmp/easyrmm-test-step); test ! -e /proc/$p || test "$(cut -d' ' -f3 /proc/$p/stat)" = Z`

// scriptStepsStopped: a cancel or the job's time limit (SIGTERM to the
// script's process group, as the agent sends) stops a step running through
// t too, though timeout runs it in a process group of its own, and the run
// releases its lock at once. A run killed outright (SIGKILL) leaves that
// step running: its lock holds until the step ends, and then no longer.
func scriptStepsStopped(t *testing.T, c *scriptContainer) {
	pm := c.slowRefresh(t)
	start := func() {
		c.sh(t, "rm -rf "+stateDir)
		docker(t, "exec", "-d", c.name, "setsid", "sh", "-c", "echo $$ >/tmp/pgid; exec sh "+scriptPath+" apply integrity time-limit=3600")
		c.waitFor(t, "/tmp/easyrmm-test-step")
	}
	ended := `p=$(cat /tmp/pgid); test ! -e /proc/$p || test "$(cut -d' ' -f3 /proc/$p/stat)" = Z`

	start()
	sent := time.Now()
	c.sh(t, "kill -TERM -$(cat /tmp/pgid)")
	c.waitUntil(t, ended, "the run to end")
	// Before the agent's SIGKILL, ten seconds after its SIGTERM.
	if took := time.Since(sent); took > 8*time.Second {
		t.Errorf("the run took %s to end after SIGTERM", took)
	}
	c.waitUntil(t, stepGone, "the step to be stopped")
	c.wantGone(t, stateDir+"/lock")

	c.sh(t, "rm -f /tmp/easyrmm-test-step")
	start()
	c.sh(t, "kill -KILL -$(cat /tmp/pgid)")
	c.waitUntil(t, ended, "the run to end")
	if _, _, code := c.run(t, "sh", "-c", stepGone); code == 0 {
		t.Fatal("the step ended with the run killed outright; this test needs it still running")
	}
	c.sh(t, "chmod 0666 /etc/passwd")
	m := scriptModule(t, parseScriptOutcome(t, c.script(t, "apply", "permissions"), HardeningApply, []string{"permissions"}), "permissions")
	if m.Outcome != HardeningRefused || !strings.Contains(m.OutcomeReason, "Another EasyRMM hardening run") {
		t.Errorf("apply while a killed run's step still runs: %+v", m)
	}
	c.sh(t, "kill -KILL $(cat /tmp/easyrmm-test-step)")
	c.waitUntil(t, stepGone, "the step to end")
	m = scriptModule(t, parseScriptOutcome(t, c.script(t, "apply", "permissions"), HardeningApply, []string{"permissions"}), "permissions")
	if m.Outcome != HardeningApplied {
		t.Errorf("apply once the killed run's step ended: %+v", m)
	}
	c.sh(t, "rm -rf "+stateDir+" /usr/local/sbin/"+pm+" /tmp/easyrmm-test-step /tmp/pgid && chmod 0644 /etc/passwd")
}

// scriptTimeLimit: the job's time limit (time-limit, which the server gives
// every mode) bounds every step. A module does not start with less than a
// minute left; a package step not without its minimum; a step that would
// run past the job's end is stopped there, and the run ends within the
// limit. The modules after one that ran out of time are not run. Copies of
// the script lower the minimums where the test needs a module to start.
func scriptTimeLimit(t *testing.T, c *scriptContainer) {
	const short, noInstall, noRemove = "/tmp/easyrmm-short-time.sh", "/tmp/easyrmm-no-install.sh", "/tmp/easyrmm-no-remove.sh"
	c.sh(t, "sed -e 's/^MODULE_MIN=60$/MODULE_MIN=5/' -e 's/^PKG_INSTALL_MIN=300$/PKG_INSTALL_MIN=5/' "+scriptPath+" >"+short+
		" && sed 's/^PKG_INSTALL_MIN=300$/PKG_INSTALL_MIN=100000/' "+scriptPath+" >"+noInstall+
		" && sed 's/^PKG_REMOVE_MIN=120$/PKG_REMOVE_MIN=100000/' "+scriptPath+" >"+noRemove+
		" && grep -c '^MODULE_MIN=5$\\|^PKG_INSTALL_MIN=5$' "+short+" | grep -qx 2 && grep -q '^PKG_INSTALL_MIN=100000$' "+noInstall+
		" && grep -q '^PKG_REMOVE_MIN=100000$' "+noRemove)
	run := func(script string, args ...string) (*hardeningResult, time.Duration) {
		t.Helper()
		start := time.Now()
		out, errOut, code := c.run(t, append([]string{"sh", script}, args...)...)
		if code != 0 {
			t.Fatalf("%q: exit %d\n%s\n%s", args, code, out, errOut)
		}
		return parseScriptOutcome(t, out, args[0], strings.Split(args[1], ",")), time.Since(start)
	}

	// A minute's limit leaves less than a module's minute.
	c.sh(t, "rm -rf "+stateDir+" && chmod 0666 /etc/passwd")
	r, _ := run(scriptPath, "apply", "permissions", "time-limit=60")
	if m := scriptModule(t, r, "permissions"); m.Outcome != HardeningNotRun || !strings.Contains(m.OutcomeReason, "time ran out") ||
		m.State != HardeningFailed || m.Recorded {
		t.Errorf("a module with less than a minute left: %+v", m)
	}
	c.wantModes(t, "666 /etc/passwd")

	// A refresh that would take five minutes is stopped at the end of the
	// job's time for changes (30 seconds into a minute's limit).
	pm := c.slowRefresh(t)
	r, took := run(short, "apply", "permissions,integrity", "time-limit=60")
	if took >= time.Minute {
		t.Errorf("a run with a minute's limit took %s", took)
	}
	if m := scriptModule(t, r, "permissions"); m.Outcome != HardeningApplied {
		t.Errorf("permissions, before the time ran out: %+v", m)
	}
	if m := scriptModule(t, r, "integrity"); m.Outcome != HardeningOutcomeFailed ||
		!strings.Contains(m.OutcomeReason, "the package manager was stopped at the end of the job's time") || m.Recorded {
		t.Errorf("integrity, whose refresh ran past the job's time: %+v", m)
	}
	c.waitUntil(t, stepGone, "the refresh to be stopped")
	c.sh(t, "rm -f /usr/local/sbin/"+pm)

	// An installation is not started without its minimum.
	r, _ = run(noInstall, "apply", "integrity", "time-limit=600")
	if m := scriptModule(t, r, "integrity"); m.Outcome != HardeningOutcomeFailed ||
		!strings.Contains(m.OutcomeReason, "not enough of the job's time was left to install") || m.Recorded {
		t.Errorf("an installation without its minimum: %+v", m)
	}

	// Undo, last module first: a removal not started without its minimum
	// fails integrity, which keeps its record, and permissions is not run.
	keep := "tar"
	if c.has(t, "dpkg-query") {
		keep = "e2fsprogs"
	}
	c.record(t, "integrity", "pkg\t"+c.token(t, keep))
	r, _ = run(noRemove, "undo", "permissions,integrity", "time-limit=600")
	if m := scriptModule(t, r, "integrity"); m.Outcome != HardeningOutcomeFailed ||
		!strings.Contains(m.OutcomeReason, "not enough of the job's time was left to remove") || !m.Recorded {
		t.Errorf("integrity, a removal without its minimum: %+v", m)
	}
	if m := scriptModule(t, r, "permissions"); m.Outcome != HardeningNotRun || !m.Recorded {
		t.Errorf("permissions, after the time ran out: %+v", m)
	}
	c.wantModes(t, "644 /etc/passwd")
	r, _ = run(scriptPath, "undo", "permissions", "time-limit=600")
	if m := scriptModule(t, r, "permissions"); m.Outcome != HardeningUndone {
		t.Errorf("permissions undone with time enough: %+v", m)
	}
	c.wantModes(t, "666 /etc/passwd")
	c.sh(t, "rm -rf "+stateDir+" "+short+" "+noInstall+" "+noRemove+" /tmp/easyrmm-test-step && chmod 0644 /etc/passwd")
}

// scriptPackageStamps: undo removes a package only as apply installed it:
// one upgraded or installed again since (another version or install time
// than the record's) is left, and said so.
func scriptPackageStamps(t *testing.T, c *scriptContainer) {
	pkg := "tar"
	if c.has(t, "dpkg-query") {
		pkg = "e2fsprogs"
	}
	token := c.token(t, pkg)
	name, stamp, _ := strings.Cut(token, "/")
	version, _, _ := strings.Cut(stamp, "/")
	for _, tc := range []struct{ token, why string }{
		{name + "/" + version + "/1", "Left as it is: the package " + name + ", installed again since apply"},
		{name + "/0:0.0-easyrmm/1", "Left as it is: the package " + name + ", upgraded since apply (now " + version + ", then 0:0.0-easyrmm)"},
	} {
		c.sh(t, "rm -rf "+stateDir)
		c.record(t, "sudo", "pkg\t"+tc.token)
		m := scriptModule(t, parseScriptOutcome(t, c.script(t, "undo", "sudo"), HardeningUndo, []string{"sudo"}), "sudo")
		if m.Outcome != HardeningPartlyUndone || !slices.Equal(m.Done, []string{tc.why}) || m.Recorded {
			t.Errorf("undo of %s: %+v, want %q", tc.token, m, tc.why)
		}
		if got := c.token(t, pkg); got != token {
			t.Errorf("%s after undo: %s, was %s", pkg, got, token)
		}
	}
	// A record whose package is not a token is left whole, unread.
	c.sh(t, "rm -rf "+stateDir)
	c.record(t, "sudo", "pkg\t"+name+" *")
	m := scriptModule(t, parseScriptOutcome(t, c.script(t, "undo", "sudo"), HardeningUndo, []string{"sudo"}), "sudo")
	if m.Outcome != HardeningPartlyUndone || !slices.Equal(m.Done, []string{"Left as it is: the packages it installed: the record names them in a form this script does not know"}) {
		t.Errorf("undo of a record that names no token: %+v", m)
	}
	c.sh(t, "rm -rf "+stateDir)
}

// scriptConffiles: undo purges a package apply installed only while its
// configuration files are as apply recorded them; one changed since is
// kept, its package removed, not purged. Debian and Ubuntu.
func scriptConffiles(t *testing.T, c *scriptContainer) {
	if !c.has(t, "dpkg-deb") {
		return
	}
	const name, conf = "easyrmm-test-conf", "/etc/easyrmm-test.conf"
	c.buildDeb(t, name, "", "/DEBIAN/conffiles "+conf+"\\n", conf+" shipped\\n")
	install := func() {
		c.sh(t, "rm -rf "+stateDir+" && { dpkg --purge "+name+" >/dev/null 2>&1; true; } && dpkg -i /tmp/"+name+".deb >/dev/null")
		c.record(t, "sudo", "pkg\t"+c.token(t, name), "conffile\t"+name+"\t"+conf+"\t"+strings.TrimSpace(c.sh(t, "md5sum <"+conf+" | cut -c1-32")))
	}

	install()
	c.sh(t, "echo 'an administrator was here' >>"+conf)
	m := scriptModule(t, parseScriptOutcome(t, c.script(t, "undo", "sudo"), HardeningUndo, []string{"sudo"}), "sudo")
	want := []string{"Removed the packages it installed: " + name,
		"Left as it is: the configuration files of " + name + ", changed since apply (" + conf + "): the package was removed and they were kept"}
	if m.Outcome != HardeningPartlyUndone || !slices.Equal(m.Done, want) {
		t.Errorf("undo after a configuration file changed: %+v, want %q", m, want)
	}
	if got := c.sh(t, "dpkg-query -W -f='${db:Status-Abbrev}' "+name+" && grep -c administrator "+conf); got != "rc 1\n" {
		t.Errorf("the package and its changed file after undo: %q", got)
	}

	install()
	m = scriptModule(t, parseScriptOutcome(t, c.script(t, "undo", "sudo"), HardeningUndo, []string{"sudo"}), "sudo")
	if m.Outcome != HardeningUndone || !slices.Equal(m.Done, []string{"Removed the packages it installed: " + name}) {
		t.Errorf("undo with its configuration file as installed: %+v", m)
	}
	c.sh(t, "! dpkg-query -W "+name+" >/dev/null 2>&1 && test ! -e "+conf+" && rm -rf "+stateDir+" /tmp/"+name+".deb")
}

// scriptHalfInstalledBefore: a package dpkg had left half configured before
// apply is not one apply's installation added, though the installation
// configured it: the rollback of the failed apply leaves it. Debian and
// Ubuntu.
func scriptHalfInstalledBefore(t *testing.T, c *scriptContainer) {
	if !c.has(t, "dpkg-deb") {
		return
	}
	const name = "easyrmm-test-half"
	c.buildDeb(t, name, "", "/DEBIAN/postinst #!/bin/sh\\n! test -e /tmp/easyrmm-test-fail\\n")
	c.sh(t, "rm -rf "+stateDir+" && touch /tmp/easyrmm-test-fail && { dpkg -i /tmp/"+name+".deb >/dev/null 2>&1; true; } && "+
		"test \"$(dpkg-query -W -f='${db:Status-Abbrev}' "+name+")\" = 'iF '")
	c.standIn(t, "apt-get", `*" update "*) exit 0 ;;`+"\n"+
		`*" install "*) rm -f /tmp/easyrmm-test-fail; dpkg --configure `+name+` >/dev/null; echo "E: stopped by the test" >&2; exit 100 ;;`)
	m := scriptModule(t, parseScriptOutcome(t, c.script(t, "apply", "integrity"), HardeningApply, []string{"integrity"}), "integrity")
	c.sh(t, "rm -f /usr/local/sbin/apt-get")
	if m.Outcome != HardeningOutcomeFailed || m.OutcomeReason != "AIDE could not be installed: E: stopped by the test; what this run changed was put back." {
		t.Errorf("a failed apply that configured a half-installed package: %+v", m)
	}
	if got := strings.TrimSpace(c.sh(t, "dpkg-query -W -f='${db:Status-Abbrev}' "+name)); got != "ii" {
		t.Errorf("the half-installed package after the rollback: %q", got)
	}
	c.sh(t, "dpkg --purge "+name+" >/dev/null && rm -rf "+stateDir+" /tmp/"+name+".deb")
}

// scriptNoRemove: an installation never removes a package. Where the
// packages apply installs would conflict with one installed, apply fails
// (apt-get --no-remove) and the package stays. A stand-in apt-get installs
// a package that conflicts with one installed in AIDE's place. Debian and
// Ubuntu.
func scriptNoRemove(t *testing.T, c *scriptContainer) {
	if !c.has(t, "dpkg-deb") {
		return
	}
	c.buildDeb(t, "easyrmm-test-victim", "")
	c.buildDeb(t, "easyrmm-test-conflict", "Conflicts: easyrmm-test-victim\\n")
	c.sh(t, "rm -rf "+stateDir+" && dpkg -i /tmp/easyrmm-test-victim.deb >/dev/null")
	// Every option apply gives, then the conflicting package in place of
	// those asked for.
	c.standIn(t, "apt-get", `*" update "*) exit 0 ;;`+"\n"+
		`*" install "*) o=; for a in "$@"; do [ "$a" = install ] && break; o="$o $a"; done; exec /usr/bin/apt-get $o install /tmp/easyrmm-test-conflict.deb ;;`)
	m := scriptModule(t, parseScriptOutcome(t, c.script(t, "apply", "integrity"), HardeningApply, []string{"integrity"}), "integrity")
	c.sh(t, "rm -f /usr/local/sbin/apt-get")
	if m.Outcome != HardeningOutcomeFailed || m.Recorded ||
		!strings.HasPrefix(m.OutcomeReason, "AIDE could not be installed: E: Packages need to be removed but remove is disabled") ||
		!strings.HasSuffix(m.OutcomeReason, "; what this run changed was put back.") {
		t.Errorf("an installation that would remove a package: %+v", m)
	}
	if got := c.sh(t, "dpkg-query -W -f='${db:Status-Abbrev}\\n' easyrmm-test-victim; dpkg-query -W easyrmm-test-conflict >/dev/null 2>&1 || echo none"); got != "ii \nnone\n" {
		t.Errorf("the installed package, and the one that conflicts with it: %q", got)
	}
	c.sh(t, "dpkg --purge easyrmm-test-victim >/dev/null && rm -rf "+stateDir+" /tmp/easyrmm-test-victim.deb /tmp/easyrmm-test-conflict.deb")
}

// scriptMarker: undo of audit reads the auditd marker only in a directory
// of root's alone (not a link, not writable by others), and only package
// tokens in it, as words: otherwise it leaves auditd's packages, and says
// why.
func scriptMarker(t *testing.T, c *scriptContainer) {
	const dir, marker = "/var/lib/easyrmm", "/var/lib/easyrmm/auditd-installed"
	pkg := "glibc"
	if c.has(t, "dpkg-query") {
		pkg = "libc6"
	}
	token := c.token(t, pkg)
	notRead := "Left as it is: auditd, which EasyRMM installed: " + dir + " is not a directory, not a link, that root owns and root alone may write, so " + marker + " is not read"
	for _, tc := range []struct{ setup, tokens, want string }{
		{"mkdir -p /tmp/easyrmm-elsewhere && ln -s /tmp/easyrmm-elsewhere " + dir, token, notRead},
		{"mkdir -m 0777 " + dir, token, notRead},
		{"mkdir -m 0755 " + dir, "*", "Left as it is: auditd, which EasyRMM installed: " + marker + " names its packages in a form this script does not know, so they were left"},
	} {
		c.sh(t, "rm -rf "+stateDir+" "+dir+" /tmp/easyrmm-elsewhere && "+tc.setup+" && printf '# a marker\\n%s\\n' '"+tc.tokens+"' >"+marker)
		c.record(t, "audit", "dir\t/tmp/easyrmm-test-audit")
		m := scriptModule(t, parseScriptOutcome(t, c.script(t, "undo", "audit"), HardeningUndo, []string{"audit"}), "audit")
		if m.Outcome != HardeningPartlyUndone || !slices.Equal(m.Done, []string{tc.want}) {
			t.Errorf("undo with %s: %+v, want %q", tc.setup, m, tc.want)
		}
		if got := c.token(t, pkg); got != token {
			t.Errorf("%s after undo: %s", pkg, got)
		}
	}
	c.sh(t, "rm -rf "+stateDir+" "+dir+" /tmp/easyrmm-elsewhere")
}

// scriptGenerated: a file a program apply started made (here AIDE's
// baseline) goes with undo only as it was made: by its sum in the record,
// or, made after apply ended, in the sums its maker wrote beside the
// record. One changed since, or of a sum not known, is left, and said so.
func scriptGenerated(t *testing.T, c *scriptContainer) {
	const db, dbNew = "/var/lib/aide/aide.db.gz", "/var/lib/aide/aide.db.new.gz"
	c.sh(t, "rm -rf "+stateDir+" && mkdir -p /var/lib/aide && echo made >"+db+" && echo made >"+dbNew)
	sum := strings.TrimSpace(c.sh(t, "sha256sum <"+db+" | cut -c1-64"))
	c.record(t, "integrity", "gen\t"+db+"\t"+sum, "gen\t"+dbNew+"\t?")
	c.sh(t, "echo changed >>"+db)
	m := scriptModule(t, parseScriptOutcome(t, c.script(t, "undo", "integrity"), HardeningUndo, []string{"integrity"}), "integrity")
	want := []string{"Left as it is: " + dbNew + ": whether it changed since apply made it is not known",
		"Left as it is: " + db + ", changed since apply made it"}
	if m.Outcome != HardeningPartlyUndone || !slices.Equal(m.Done, want) {
		t.Errorf("undo of changed generated files: %+v, want %q", m, want)
	}
	c.sh(t, "test -e "+db+" && test -e "+dbNew)

	// As made: by the record's sum, and by the sums its maker wrote.
	c.sh(t, "rm -rf "+stateDir+" && echo made >"+db)
	c.record(t, "integrity", "gen\t"+db+"\t"+sum, "gen\t"+dbNew+"\t?")
	c.sh(t, "printf '%s %s\\n' \"$(sha256sum <"+dbNew+" | cut -c1-64)\" "+dbNew+" >"+stateDir+"/modules/integrity/files/gen-sums")
	m = scriptModule(t, parseScriptOutcome(t, c.script(t, "undo", "integrity"), HardeningUndo, []string{"integrity"}), "integrity")
	if m.Outcome != HardeningUndone || !slices.Equal(m.Done, []string{"Removed " + dbNew, "Removed " + db}) {
		t.Errorf("undo of generated files as made: %+v", m)
	}
	c.sh(t, "test ! -e "+db+" && test ! -e "+dbNew+" && rm -rf /var/lib/aide "+stateDir)
}

// scriptLinks: a file apply changes that is a symbolic link stays one: apply
// and undo write the file it points to. Here /etc/inetd.conf, with telnet
// on through a stand-in inetd.
func scriptLinks(t *testing.T, c *scriptContainer) {
	const target = "/etc/easyrmm-test-inetd.conf"
	const line = "telnet stream tcp nowait root /usr/sbin/tcpd /usr/sbin/in.telnetd"
	c.sh(t, "rm -rf "+stateDir+" && printf '%s\\n' '"+line+"' >"+target+" && ln -s "+target+" /etc/inetd.conf && "+
		"printf '#!/bin/sh\\nexit 0\\n' >/usr/local/sbin/inetd && chmod 0755 /usr/local/sbin/inetd")
	m := scriptModule(t, parseScriptOutcome(t, c.script(t, "apply", "services"), HardeningApply, []string{"services"}), "services")
	if m.Outcome != HardeningApplied {
		t.Errorf("services applied with /etc/inetd.conf a link: %+v", m)
	}
	if got := c.sh(t, "readlink /etc/inetd.conf && cat "+target); got != target+"\n#<off by EasyRMM># "+line+"\n" {
		t.Errorf("after apply, the link and the file it points to: %q", got)
	}
	m = scriptModule(t, parseScriptOutcome(t, c.script(t, "undo", "services"), HardeningUndo, []string{"services"}), "services")
	if m.Outcome != HardeningUndone || !slices.Equal(m.Done, []string{"Put back /etc/inetd.conf"}) {
		t.Errorf("services undone with /etc/inetd.conf a link: %+v", m)
	}
	if got := c.sh(t, "readlink /etc/inetd.conf && cat "+target); got != target+"\n"+line+"\n" {
		t.Errorf("after undo, the link and the file it points to: %q", got)
	}
	c.sh(t, "rm -f /etc/inetd.conf "+target+" /usr/local/sbin/inetd && rm -rf "+stateDir)
}

// scriptFirewallNeedsFail2ban: undo refuses the firewall alone while
// fail2ban's applied configuration, which bans with it, remains, and names
// fail2ban for the console to choose with it; the two together are undone.
func scriptFirewallNeedsFail2ban(t *testing.T, c *scriptContainer) {
	const fw, f2b = "/tmp/easyrmm-test-fw", "/tmp/easyrmm-test-f2b"
	c.sh(t, "rm -rf "+stateDir+" && mkdir -p "+fw+" "+f2b)
	c.record(t, "firewall", "dir\t"+fw)
	c.record(t, "fail2ban", "dir\t"+f2b)
	m := scriptModule(t, parseScriptOutcome(t, c.script(t, "undo", "firewall"), HardeningUndo, []string{"firewall"}), "firewall")
	if m.Outcome != HardeningRefused || !strings.Contains(m.OutcomeReason, "Undo fail2ban with it") ||
		!slices.Equal(m.UndoWith, []string{"fail2ban"}) || !m.Recorded {
		t.Errorf("undo of the firewall alone while fail2ban is applied: %+v", m)
	}
	c.sh(t, "test -d "+fw)
	r := parseScriptOutcome(t, c.script(t, "undo", "firewall,fail2ban"), HardeningUndo, []string{"firewall", "fail2ban"})
	for _, m := range r.Modules {
		if m.Outcome != HardeningUndone || len(m.UndoWith) > 0 {
			t.Errorf("%s undone with the other: %+v", m.Module, m)
		}
	}
	c.wantGone(t, fw)
	c.wantGone(t, f2b)
	c.wantGone(t, stateDir)
}

// scriptUSBFstab: usb-storage is refused where /etc/fstab mounts a
// filesystem on a USB disk at boot without nofail, mounted now or not: the
// computer would not boot. The container passes for a computer (a stand-in
// systemd-detect-virt, and neither /.dockerenv nor Ubuntu's
// /run/systemd/container), with stand-ins for the commands that read
// modules and disks. Debian and Ubuntu, whose images name no container in
// PID 1's environment.
func scriptUSBFstab(t *testing.T, c *scriptContainer) {
	if !c.has(t, "dpkg-query") {
		return
	}
	stub := func(name, body string) string {
		return "printf '%s\\n' '#!/bin/sh' '" + strings.ReplaceAll(body, "'", `'"'"'`) + "' >/usr/local/sbin/" + name + " && chmod 0755 /usr/local/sbin/" + name
	}
	c.sh(t, "rm -rf "+stateDir+" && { cp -p /etc/fstab /tmp/easyrmm-fstab 2>/dev/null || : >/tmp/easyrmm-fstab; } && rm -f /.dockerenv && "+
		"{ ! test -e /run/systemd/container || mv /run/systemd/container /tmp/easyrmm-container; } && "+
		stub("systemd-detect-virt", "echo none; exit 1")+" && "+
		stub("modprobe", "exit 0")+" && "+
		stub("modinfo", "echo /lib/modules/test/kernel/drivers/usb/storage/usb-storage.ko")+" && "+
		stub("blkid", `case "$*" in *UUID=0123-4567*) echo /dev/sdz1 ;; *) exit 2 ;; esac`)+" && "+
		stub("lsblk", `case "$*" in *NAME,TRAN*) echo 'NAME="/dev/sdz" TRAN="usb"' ;; *-nrspo*/dev/sdz1*) printf '\nusb\n' ;; esac`))
	defer c.sh(t, "cp -p /tmp/easyrmm-fstab /etc/fstab && touch /.dockerenv && { ! test -e /tmp/easyrmm-container || mv /tmp/easyrmm-container /run/systemd/container; } && "+
		"rm -f /tmp/easyrmm-fstab /usr/local/sbin/systemd-detect-virt "+
		"/usr/local/sbin/modprobe /usr/local/sbin/modinfo /usr/local/sbin/blkid /usr/local/sbin/lsblk")
	for _, tc := range []struct{ options, want string }{
		{"defaults", "Refused: /etc/fstab mounts a filesystem or swap on a USB disk at boot, without nofail (UUID=0123-4567 (/mnt/backup)), and the computer would not boot without usb-storage"},
		{"defaults,nofail", "Keep usb-storage from loading, in /etc/modprobe.d and the initramfs: USB disks and backup drives stop working"},
	} {
		c.sh(t, "cp -p /tmp/easyrmm-fstab /etc/fstab && echo 'UUID=0123-4567 /mnt/backup ext4 "+tc.options+" 0 2' >>/etc/fstab")
		r := parseScriptResult(t, c.script(t, "check", "usb-storage"), []string{"usb-storage"})
		if m := scriptModule(t, r, "usb-storage"); r.Platform.Container != "none" || !slices.Contains(m.Changes, tc.want) {
			t.Errorf("usb-storage with a USB disk in /etc/fstab (%s): %+v on %+v, want %q", tc.options, m, r.Platform, tc.want)
		}
	}
	c.wantGone(t, stateDir)
}

// scriptStreams: a dnf module stream's file that was there before, and that
// an installation changed, is put back as it was by the rollback of the
// module that failed; and undo puts a stream back only after the packages
// that need it are gone, so that it leaves one whose packages stay. Stand-in
// dnf and rpm, first in the script's PATH. Only where dnf is the package
// manager.
func scriptStreams(t *testing.T, c *scriptContainer) {
	if !c.has(t, "dnf") {
		return
	}
	const stream = "/etc/dnf/modules.d/easyrmm-test.module"
	const before = "[easyrmm-test]\nname=easyrmm-test\nstream=1\nprofiles=\nstate=enabled\n"
	c.sh(t, "rm -rf "+stateDir+" && mkdir -p /etc/dnf/modules.d && printf '"+strings.ReplaceAll(before, "\n", `\n`)+"' >"+stream)
	c.standIn(t, "dnf", `*" install "*) sed -i 's/^stream=1$/stream=2/' `+stream+`; echo "Error: stopped by the test" >&2; exit 1 ;;`+"\n"+`*) exit 0 ;;`)
	m := scriptModule(t, parseScriptOutcome(t, c.script(t, "apply", "integrity"), HardeningApply, []string{"integrity"}), "integrity")
	c.sh(t, "rm -f /usr/local/sbin/dnf")
	if m.Outcome != HardeningOutcomeFailed || m.OutcomeReason != "AIDE could not be installed: Error: stopped by the test; what this run changed was put back." {
		t.Errorf("a failed apply that changed a module stream: %+v", m)
	}
	if got := c.sh(t, "cat "+stream); got != before {
		t.Errorf("the stream's file after the rollback: %q, want %q", got, before)
	}

	// Undo: the packages first, which the package manager refuses to
	// remove; the stream they need stays.
	c.sh(t, "rm -rf "+stateDir)
	c.record(t, "integrity", "stream\t"+stream+"\t-\t-\t"+strings.TrimSpace(c.sh(t, "sha256sum <"+stream+" | cut -c1-64")), "pkg\t"+c.token(t, "tar"))
	c.standIn(t, "rpm", `*" --test "*) ;;`+"\n"+`*" -e "*) echo 'error: refused by the test' >&2; exit 1 ;;`)
	m = scriptModule(t, parseScriptOutcome(t, c.script(t, "undo", "integrity"), HardeningUndo, []string{"integrity"}), "integrity")
	c.sh(t, "rm -f /usr/local/sbin/rpm")
	if want := "Left as it is: " + stream + ", the module stream the packages that stay need"; m.Outcome != HardeningPartlyUndone || !slices.Contains(m.Done, want) {
		t.Errorf("undo whose packages stay: %+v, want %q", m, want)
	}
	c.sh(t, "test -f "+stream+" && rm -rf "+stateDir+" "+stream)
}
