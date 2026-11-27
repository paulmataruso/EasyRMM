package logcollect

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Linux names of the collector's unit and state (ADR-0060).
const (
	UnitName        = "easyrmm-agent-collect.service"
	UnitPath        = "/etc/systemd/system/" + UnitName
	StateDirName    = "easyrmm-collect"
	SpoolDir        = "/var/lib/" + StateDirName
	AuditSocketName = "audit.sock"
)

// Unit is the systemd unit of the collector: an unnamed user of its own, no
// capability, no network, no access to the agent's state, a fifth of one
// processor and 256 MiB. agentUnit is the agent's unit, which the collector is
// part of. The journal is read through the journal's group; auditd's log
// arrives as descriptors over the socket in the spool.
func Unit(exe, agentUnit string) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w("# Written by easyrmm-agent; changes are replaced. See ADR-0060.")
	w("[Unit]")
	w("Description=EasyRMM log collector")
	w("PartOf=%s", agentUnit)
	w("After=%s", agentUnit)
	w("")
	w("[Service]")
	w("Type=simple")
	w("ExecStart=%s collect --spool %s --audit-socket %s/%s", exe, SpoolDir, SpoolDir, AuditSocketName)
	w("Restart=on-failure")
	w("RestartSec=15")
	w("DynamicUser=yes")
	w("SupplementaryGroups=systemd-journal")
	w("StateDirectory=%s", StateDirName)
	w("StateDirectoryMode=0700")
	w("NoNewPrivileges=yes")
	w("CapabilityBoundingSet=")
	w("AmbientCapabilities=")
	w("ProtectSystem=strict")
	w("ProtectHome=yes")
	w("PrivateTmp=yes")
	w("PrivateDevices=yes")
	w("ProtectKernelTunables=yes")
	w("ProtectKernelModules=yes")
	w("ProtectControlGroups=yes")
	w("RestrictSUIDSGID=yes")
	w("LockPersonality=yes")
	w("MemoryDenyWriteExecute=yes")
	w("InaccessiblePaths=/var/lib/easyrmm-agent /var/lib/easyrmm-hardening /run/systemd/resolve /run/dbus")
	w("RestrictAddressFamilies=AF_UNIX")
	w("IPAddressDeny=any")
	w("CPUQuota=20%%")
	w("MemoryHigh=192M")
	w("MemoryMax=256M")
	w("Nice=10")
	w("IOWeight=10")
	w("")
	w("[Install]")
	w("WantedBy=multi-user.target")
	return b.String()
}

// Systemctl runs systemctl; replaced by tests.
var Systemctl = func(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput() //nolint:gosec // fixed program, arguments built in this package
	if err != nil {
		return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// InstallUnit writes the unit to path and starts it.
func InstallUnit(path, exe, agentUnit string) error {
	if err := os.WriteFile(path, []byte(Unit(exe, agentUnit)), 0o644); err != nil { //nolint:gosec // a unit file is world-readable
		return err
	}
	if err := Systemctl("daemon-reload"); err != nil {
		return err
	}
	return Systemctl("enable", "--now", UnitName)
}

// RemoveUnit stops the unit and removes its file; a unit that is not there is
// not an error.
func RemoveUnit(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	_ = Systemctl("disable", "--now", UnitName)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return Systemctl("daemon-reload")
}
